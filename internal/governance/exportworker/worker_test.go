package exportworker_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/export/evidence"
)

// memBlob is an in-memory BlobClient used to drive worker tests without
// hitting MinIO or the local filesystem.
type memBlob struct {
	store map[string][]byte
}

func newMemBlob() *memBlob { return &memBlob{store: map[string][]byte{}} }

func (m *memBlob) Put(key string, r io.Reader) (int64, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	m.store[key] = buf
	return int64(len(buf)), nil
}
func (m *memBlob) Get(key string) (io.ReadCloser, error) {
	if b, ok := m.store[key]; ok {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	return nil, evidence.ErrBlobNotFound
}
func (m *memBlob) Delete(key string) error { delete(m.store, key); return nil }
func (m *memBlob) Exists(key string) bool  { _, ok := m.store[key]; return ok }

// TestMemBlob_Roundtrip is a sanity check on the in-memory BlobClient used
// by other tests in this package — keeps it from silently rotting if the
// BlobClient interface ever drifts.
func TestMemBlob_Roundtrip(t *testing.T) {
	b := newMemBlob()
	if _, err := b.Put("a/b.zip", bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !b.Exists("a/b.zip") {
		t.Errorf("Exists should be true")
	}
	rc, err := b.Get("a/b.zip")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, _ := io.ReadAll(rc)
	if string(got) != "hello" {
		t.Errorf("got %q want hello", got)
	}
	_ = b.Delete("a/b.zip")
	if b.Exists("a/b.zip") {
		t.Errorf("Exists should be false after Delete")
	}
}
