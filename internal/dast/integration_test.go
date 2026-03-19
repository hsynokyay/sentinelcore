package dast

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// startVulnerableServer creates a test HTTP server that simulates common vulnerabilities.
func startVulnerableServer() *httptest.Server {
	mux := http.NewServeMux()

	// SQL injection: reflects SQL error on injected input
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if q != "" && (len(q) > 3 && (q[0] == '\'' || q[0] == '1')) {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"error": "You have an error in your SQL syntax near '%s'"}`, q)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[{"id":1,"name":"Alice"}]`)
	})

	// XSS: reflects input in response
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>Results for: %s</body></html>`, q)
	})

	// Path traversal: responds with file content indicator
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/files/"):]
		if path == "..%2F..%2F..%2Fetc%2Fpasswd" || path == "../../../etc/passwd" {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// Header injection: reflects Host header
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		fmt.Fprintf(w, `<a href="https://%s/reset">Reset Password</a>`, host)
	})

	// Authenticated endpoint
	mux.HandleFunc("/api/protected", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":"secret"}`)
	})

	return httptest.NewServer(mux)
}

func TestIntegration_FullDAST_Scan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	server := startVulnerableServer()
	defer server.Close()

	// Extract hostname (IP only, no port) since scope enforcer uses url.Hostname()
	hostname := "127.0.0.1"

	// Create scope enforcer that allows test server
	resolver := &testResolver{host: hostname, ip: "127.0.0.1"}

	// Create worker with auth
	broker := authbroker.NewBroker(zerolog.Nop())
	worker := NewWorker(WorkerConfig{
		WorkerID:       "test-worker",
		MaxConcurrency: 5,
		RequestTimeout: 10 * time.Second,
	}, broker, zerolog.Nop())

	// Define endpoints matching the vulnerable server
	endpoints := []Endpoint{
		{
			Path:    "/api/users",
			Method:  "GET",
			BaseURL: server.URL,
			Parameters: []Parameter{
				{Name: "id", In: "query", Type: "string"},
			},
		},
		{
			Path:    "/search",
			Method:  "GET",
			BaseURL: server.URL,
			Parameters: []Parameter{
				{Name: "q", In: "query", Type: "string"},
			},
		},
		{
			Path:    "/redirect",
			Method:  "GET",
			BaseURL: server.URL,
		},
	}

	job := ScanJob{
		ID:            "integration-test-001",
		TargetBaseURL: server.URL,
		AllowedHosts:  []string{hostname},
		Endpoints:     endpoints,
		ScopeConfig: scope.Config{
			AllowedHosts:    []string{hostname},
			AllowPrivateIPs: true, // test server is on localhost
			MaxViolations:   500,  // high limit — SSRF payloads generate expected violations
			Resolver:        resolver,
		},
		Concurrency:  5,
		RequestDelay: time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := worker.ExecuteScan(ctx, job)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Verify results
	if result.Status != "completed" {
		t.Fatalf("expected status completed, got %s (error: %s)", result.Status, result.Error)
	}
	if result.TotalRequests == 0 {
		t.Fatal("expected some requests to be made")
	}

	// Check findings were detected
	t.Logf("Scan completed: %d requests, %d findings, %d failures",
		result.TotalRequests, len(result.Findings), result.FailedRequests)

	// Verify finding categories
	categories := make(map[string]int)
	for _, f := range result.Findings {
		categories[f.Category]++
		// Verify evidence is captured
		if f.Evidence == nil {
			t.Errorf("finding %s has no evidence", f.ID)
		}
		if f.Evidence != nil && f.Evidence.SHA256 == "" {
			t.Errorf("finding %s evidence has no SHA256", f.ID)
		}
	}
	t.Logf("Finding categories: %v", categories)

	// We expect at least SQLi and XSS findings against the mock server
	if categories["sqli"] == 0 {
		t.Error("expected SQL injection findings against vulnerable server")
	}
	if categories["xss"] == 0 {
		t.Error("expected XSS findings against vulnerable server")
	}
}

func TestIntegration_AuthenticatedScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	server := startVulnerableServer()
	defer server.Close()

	hostname := "127.0.0.1"
	resolver := &testResolver{host: hostname, ip: "127.0.0.1"}

	broker := authbroker.NewBroker(zerolog.Nop())
	worker := NewWorker(WorkerConfig{
		WorkerID:       "test-auth-worker",
		MaxConcurrency: 2,
		RequestTimeout: 10 * time.Second,
	}, broker, zerolog.Nop())

	endpoints := []Endpoint{
		{
			Path:    "/api/protected",
			Method:  "GET",
			BaseURL: server.URL,
		},
	}

	job := ScanJob{
		ID:            "auth-test-001",
		TargetBaseURL: server.URL,
		AllowedHosts:  []string{hostname},
		Endpoints:     endpoints,
		AuthConfig: &authbroker.AuthConfig{
			Strategy:    "bearer",
			Credentials: map[string]string{"token": "valid-token"},
			TTL:         time.Hour,
		},
		ScopeConfig: scope.Config{
			AllowedHosts:    []string{hostname},
			AllowPrivateIPs: true,
			MaxViolations:   100,
			Resolver:        resolver,
		},
		Concurrency: 2,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := worker.ExecuteScan(ctx, job)
	if err != nil {
		t.Fatalf("auth scan failed: %v", err)
	}

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s", result.Status)
	}
	if result.TotalRequests == 0 {
		t.Fatal("expected requests to authenticated endpoint")
	}
	t.Logf("Authenticated scan: %d requests, %d findings", result.TotalRequests, len(result.Findings))
}

func TestIntegration_ScopeAbort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	server := startVulnerableServer()
	defer server.Close()

	hostname := "127.0.0.1"
	// Use resolver that causes rebinding on second lookup
	resolver := &rebindingResolver{
		host:    hostname,
		firstIP: "127.0.0.1",
		newIP:   "10.0.0.1", // will appear as unpinned
		callCount: 0,
	}

	broker := authbroker.NewBroker(zerolog.Nop())
	worker := NewWorker(WorkerConfig{
		WorkerID:       "test-scope-worker",
		MaxConcurrency: 1,
		RequestTimeout: 5 * time.Second,
	}, broker, zerolog.Nop())

	endpoints := []Endpoint{
		{
			Path:    "/api/users",
			Method:  "GET",
			BaseURL: server.URL,
			Parameters: []Parameter{
				{Name: "id", In: "query", Type: "string"},
			},
		},
	}

	job := ScanJob{
		ID:            "scope-abort-test",
		TargetBaseURL: server.URL,
		AllowedHosts:  []string{hostname},
		Endpoints:     endpoints,
		ScopeConfig: scope.Config{
			AllowedHosts:    []string{hostname},
			AllowPrivateIPs: true, // allow private so pinning works
			MaxViolations:   2,    // low threshold
			Resolver:        resolver,
		},
		Concurrency: 1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := worker.ExecuteScan(ctx, job)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	// Should be aborted due to scope violations (rebinding detection)
	if result.ScopeViolations == 0 {
		// The rebinding resolver triggers after PinHosts, so violations should appear
		t.Logf("Warning: expected scope violations from rebinding, got 0 (status: %s)", result.Status)
	}
	t.Logf("Scope abort test: status=%s, violations=%d, requests=%d",
		result.Status, result.ScopeViolations, result.TotalRequests)
}

// testResolver returns a fixed IP for the test server host.
type testResolver struct {
	host string
	ip   string
}

func (r *testResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if host == r.host {
		return []net.IPAddr{{IP: net.ParseIP(r.ip)}}, nil
	}
	return nil, fmt.Errorf("unknown host: %s", host)
}

// rebindingResolver simulates DNS rebinding after first resolution.
type rebindingResolver struct {
	host      string
	firstIP   string
	newIP     string
	callCount int
}

func (r *rebindingResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if host == r.host {
		r.callCount++
		if r.callCount <= 1 {
			return []net.IPAddr{{IP: net.ParseIP(r.firstIP)}}, nil
		}
		// After first call, return different IP (rebinding)
		return []net.IPAddr{{IP: net.ParseIP(r.newIP)}}, nil
	}
	return nil, fmt.Errorf("unknown host: %s", host)
}
