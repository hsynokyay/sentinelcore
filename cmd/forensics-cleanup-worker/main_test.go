package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minio/minio-go/v7"
)

// fakeRows implements the slice of pgx.Rows the worker uses.
type fakeRows struct {
	data    [][]any
	idx     int
	closed  bool
	scanErr error
	rowsErr error
}

func (r *fakeRows) Close()                                       { r.closed = true }
func (r *fakeRows) Err() error                                   { return r.rowsErr }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Next() bool                                   { ok := r.idx < len(r.data); r.idx++; return ok }
func (r *fakeRows) Scan(dst ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	row := r.data[r.idx-1]
	for i, d := range dst {
		switch p := d.(type) {
		case *uuid.UUID:
			*p = row[i].(uuid.UUID)
		case *[]byte:
			*p = row[i].([]byte)
		default:
			return fmt.Errorf("fakeRows: unsupported dst type %T", d)
		}
	}
	return nil
}
func (r *fakeRows) Values() ([]any, error)         { return nil, nil }
func (r *fakeRows) RawValues() [][]byte            { return nil }
func (r *fakeRows) Conn() *pgx.Conn                { return nil }

// Compile-time interface assertion.
var _ pgx.Rows = (*fakeRows)(nil)

// fakeQuerier captures the queries / exec calls so tests can assert.
type fakeQuerier struct {
	rows         *fakeRows
	queryErr     error
	execErr      error
	queryCalls   int
	execCalls    int
	lastExecArgs []any
	lastExecSQL  string
}

func (q *fakeQuerier) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	q.queryCalls++
	if q.queryErr != nil {
		return nil, q.queryErr
	}
	return q.rows, nil
}
func (q *fakeQuerier) Exec(_ context.Context, sql string, args ...any) (pgconnTag, error) {
	q.execCalls++
	q.lastExecSQL = sql
	q.lastExecArgs = args
	return pgconn.CommandTag{}, q.execErr
}

// fakeMinIO records every RemoveObject call.
type fakeMinIO struct {
	calls   []string
	failOn  map[string]error
}

func (f *fakeMinIO) RemoveObject(_ context.Context, _, key string, _ minio.RemoveObjectOptions) error {
	f.calls = append(f.calls, key)
	if err, ok := f.failOn[key]; ok {
		return err
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// TestRunOnce_HappyPath: two stale rows produce four RemoveObject calls
// followed by two UPDATE statements.
func TestRunOnce_HappyPath(t *testing.T) {
	id1, id2 := uuid.New(), uuid.New()
	q := &fakeQuerier{rows: &fakeRows{data: [][]any{
		{id1, mustJSON([]string{"bundle/a/1.png.enc", "bundle/a/2.png.enc"})},
		{id2, mustJSON([]string{"bundle/b/1.png.enc"})},
	}}}
	mc := &fakeMinIO{}

	if err := runOnce(context.Background(), q, mc, "dast-forensics", 7*24*time.Hour); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if len(mc.calls) != 3 {
		t.Fatalf("RemoveObject calls = %d want 3 (got %v)", len(mc.calls), mc.calls)
	}
	if q.execCalls != 2 {
		t.Fatalf("Exec calls = %d want 2", q.execCalls)
	}
	if !strings.Contains(q.lastExecSQL, "screenshot_refs = '[]'::jsonb") {
		t.Fatalf("UPDATE SQL did not clear refs: %q", q.lastExecSQL)
	}
}

// TestRunOnce_NoRows: zero rows means no RemoveObject and no Exec.
func TestRunOnce_NoRows(t *testing.T) {
	q := &fakeQuerier{rows: &fakeRows{}}
	mc := &fakeMinIO{}
	if err := runOnce(context.Background(), q, mc, "dast-forensics", 7*24*time.Hour); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if len(mc.calls) != 0 || q.execCalls != 0 {
		t.Fatalf("expected no side effects, got remove=%d exec=%d", len(mc.calls), q.execCalls)
	}
}

// TestRunOnce_QueryError surfaces the SELECT error as a wrapped failure.
func TestRunOnce_QueryError(t *testing.T) {
	q := &fakeQuerier{queryErr: fmt.Errorf("conn refused")}
	if err := runOnce(context.Background(), q, &fakeMinIO{}, "x", time.Hour); err == nil {
		t.Fatal("expected query error to surface")
	}
}

// TestRunOnce_RemoveObjectErrorIsLoggedNotFatal: a per-key MinIO error must
// NOT prevent the UPDATE that clears the row's refs. Otherwise a permanently
// missing object would gum up the cleanup queue indefinitely.
func TestRunOnce_RemoveObjectErrorIsLoggedNotFatal(t *testing.T) {
	id := uuid.New()
	q := &fakeQuerier{rows: &fakeRows{data: [][]any{
		{id, mustJSON([]string{"bundle/x/1.png.enc"})},
	}}}
	mc := &fakeMinIO{failOn: map[string]error{
		"bundle/x/1.png.enc": fmt.Errorf("not found"),
	}}
	if err := runOnce(context.Background(), q, mc, "dast-forensics", time.Hour); err != nil {
		t.Fatalf("runOnce should swallow remove errors, got %v", err)
	}
	if q.execCalls != 1 {
		t.Fatalf("UPDATE must run even after RemoveObject error, exec=%d", q.execCalls)
	}
}

// TestEnvDuration_Default returns the default when the env var is unset or
// malformed.
func TestEnvDuration_Default(t *testing.T) {
	if got := envDuration("DEFINITELY_NOT_SET_FORENSICS", 5*time.Second); got != 5*time.Second {
		t.Fatalf("got %s want 5s", got)
	}
	t.Setenv("BAD_DUR", "garbage")
	if got := envDuration("BAD_DUR", 9*time.Second); got != 9*time.Second {
		t.Fatalf("malformed dur should yield default, got %s", got)
	}
	t.Setenv("GOOD_DUR", "30m")
	if got := envDuration("GOOD_DUR", time.Second); got != 30*time.Minute {
		t.Fatalf("got %s want 30m", got)
	}
}
