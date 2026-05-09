package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseListFlags_Defaults(t *testing.T) {
	f, err := parseListFlags(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Status != "pending_review" {
		t.Errorf("default status = %q, want pending_review", f.Status)
	}
}

func TestParseListFlags_StatusFilter(t *testing.T) {
	f, err := parseListFlags([]string{"--status", "refresh_required"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Status != "refresh_required" {
		t.Errorf("status = %q, want refresh_required", f.Status)
	}
}

func TestParseListFlags_StatusMissingValue(t *testing.T) {
	_, err := parseListFlags([]string{"--status"})
	if err == nil {
		t.Fatal("expected error for --status with no value")
	}
}

func TestParseListFlags_UnknownFlag(t *testing.T) {
	_, err := parseListFlags([]string{"--bogus"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseReRecordFlags_HappyPath(t *testing.T) {
	f, err := parseReRecordFlags([]string{
		"11111111-1111-1111-1111-111111111111",
		"--reason", "creds rotated",
		"--start-recording",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.BundleID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("BundleID = %q", f.BundleID)
	}
	if f.Reason != "creds rotated" {
		t.Errorf("Reason = %q", f.Reason)
	}
	if !f.StartRecording {
		t.Error("StartRecording should be true")
	}
}

func TestParseReRecordFlags_BundleOnly(t *testing.T) {
	f, err := parseReRecordFlags([]string{"22222222-2222-2222-2222-222222222222"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Reason != "" {
		t.Errorf("Reason = %q, want empty", f.Reason)
	}
	if f.StartRecording {
		t.Error("StartRecording should default to false")
	}
}

func TestParseReRecordFlags_MissingBundle(t *testing.T) {
	_, err := parseReRecordFlags(nil)
	if err == nil {
		t.Fatal("expected error when bundle id missing")
	}
}

func TestParseReRecordFlags_BadUUID(t *testing.T) {
	_, err := parseReRecordFlags([]string{"not-a-uuid"})
	if err == nil {
		t.Fatal("expected error for malformed uuid")
	}
}

func TestParseReRecordFlags_UnknownFlag(t *testing.T) {
	_, err := parseReRecordFlags([]string{
		"11111111-1111-1111-1111-111111111111",
		"--bogus",
	})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestRunBundlesCommand_NoArgs(t *testing.T) {
	if err := RunBundlesCommand(nil, BundlesDeps{}); err == nil {
		t.Fatal("expected usage error")
	}
}

func TestRunBundlesCommand_UnknownSubcommand(t *testing.T) {
	if err := RunBundlesCommand([]string{"approve"}, BundlesDeps{}); err == nil {
		t.Fatal("expected unknown-subcommand error")
	}
}

// TestRunBundlesList_HTTP exercises runBundlesList against an httptest server.
func TestRunBundlesList_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("status") != "approved" {
			http.Error(w, "wrong status filter", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"bundles": []map[string]string{
				{"id": "11111111-1111-1111-1111-111111111111", "status": "approved", "target_host": "app.bank.tld"},
				{"id": "22222222-2222-2222-2222-222222222222", "status": "approved", "target_host": "api.example.com"},
			},
		})
	}))
	defer srv.Close()

	var out bytes.Buffer
	deps := BundlesDeps{
		HTTPClient: srv.Client(),
		APIBase:    srv.URL,
		APIToken:   "test-token",
		Out:        &out,
		Err:        io.Discard,
	}
	if err := runBundlesList([]string{"--status", "approved"}, deps); err != nil {
		t.Fatalf("runBundlesList: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "11111111-1111-1111-1111-111111111111\tapproved\tapp.bank.tld") {
		t.Errorf("output missing first row:\n%s", got)
	}
	if !strings.Contains(got, "22222222-2222-2222-2222-222222222222\tapproved\tapi.example.com") {
		t.Errorf("output missing second row:\n%s", got)
	}
}

func TestRunBundlesList_NoToken(t *testing.T) {
	deps := BundlesDeps{HTTPClient: http.DefaultClient, APIBase: "http://x", Out: io.Discard, Err: io.Discard}
	if err := runBundlesList(nil, deps); err == nil {
		t.Fatal("expected error when SENTINELCORE_TOKEN missing")
	}
}

// TestRunBundlesReRecord_HTTP exercises the success path against a fake server.
func TestRunBundlesReRecord_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/re-record") {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		var body reRecordRequestBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Reason != "creds rotated" {
			http.Error(w, "missing reason in body", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"new_bundle_id": "33333333-3333-3333-3333-333333333333",
			"status":        "pending_review",
		})
	}))
	defer srv.Close()

	var out, errBuf bytes.Buffer
	deps := BundlesDeps{
		HTTPClient: srv.Client(),
		APIBase:    srv.URL,
		APIToken:   "test-token",
		Out:        &out,
		Err:        &errBuf,
	}
	args := []string{
		"11111111-1111-1111-1111-111111111111",
		"--reason", "creds rotated",
		"--start-recording",
	}
	if err := runBundlesReRecord(args, deps); err != nil {
		t.Fatalf("runBundlesReRecord: %v", err)
	}
	if !strings.Contains(out.String(), "33333333-3333-3333-3333-333333333333") {
		t.Errorf("expected new bundle id in stdout, got %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "33333333-3333-3333-3333-333333333333") {
		t.Errorf("expected --start-recording hint to mention new id, got %q", errBuf.String())
	}
}

func TestRunBundlesReRecord_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bundle already superseded", http.StatusConflict)
	}))
	defer srv.Close()
	deps := BundlesDeps{
		HTTPClient: srv.Client(),
		APIBase:    srv.URL,
		APIToken:   "test-token",
		Out:        io.Discard,
		Err:        io.Discard,
	}
	err := runBundlesReRecord([]string{"11111111-1111-1111-1111-111111111111"}, deps)
	if err == nil {
		t.Fatal("expected error for HTTP 409")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error = %v, expected mention of 409", err)
	}
}
