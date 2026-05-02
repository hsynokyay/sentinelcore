package dast

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoverEndpoints_OpenAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"openapi": "3.0.0",
			"paths": {
				"/users": {
					"get": {"parameters": [{"name": "id", "in": "query", "required": false}]},
					"post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"name": {"type": "string"}}}}}}}
				},
				"/users/{id}": {
					"get": {"parameters": [{"name": "id", "in": "path", "required": true}]}
				}
			}
		}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	endpoints, err := DiscoverEndpoints(ctx, srv.URL, []string{host}, DiscoveryConfig{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	gotPaths := map[string]bool{}
	for _, ep := range endpoints {
		gotPaths[ep.Method+" "+ep.Path] = true
	}
	for _, want := range []string{"GET /users", "POST /users", "GET /users/{id}"} {
		if !gotPaths[want] {
			t.Errorf("missing endpoint %q (got %v)", want, gotPaths)
		}
	}
}

func TestDiscoverEndpoints_Sitemap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://` + r.Host + `/about</loc></url>
  <url><loc>http://` + r.Host + `/contact</loc></url>
  <url><loc>http://other-host.example/skip-me</loc></url>
</urlset>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	endpoints, err := DiscoverEndpoints(ctx, srv.URL, []string{host}, DiscoveryConfig{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	gotPaths := map[string]bool{}
	for _, ep := range endpoints {
		gotPaths[ep.Path] = true
	}
	for _, want := range []string{"/about", "/contact"} {
		if !gotPaths[want] {
			t.Errorf("missing path %q (got %v)", want, gotPaths)
		}
	}
	if gotPaths["/skip-me"] {
		t.Error("off-host URL leaked into endpoints")
	}
}

func TestDiscoverEndpoints_RobotsSitemapDirective(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`User-agent: *
Disallow: /admin/
Sitemap: http://` + r.Host + `/custom-sitemap.xml`))
	})
	mux.HandleFunc("/custom-sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://` + r.Host + `/from-robots-sitemap</loc></url>
</urlset>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	endpoints, err := DiscoverEndpoints(ctx, srv.URL, []string{host}, DiscoveryConfig{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	found := false
	for _, ep := range endpoints {
		if ep.Path == "/from-robots-sitemap" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /from-robots-sitemap from robots.txt sitemap directive")
	}
}

func TestDiscoverEndpoints_HTMLCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>
			<a href="/login">login</a>
			<a href="/dashboard?ref=home">dashboard</a>
			<a href="https://external.example/skip">external</a>
		</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	endpoints, err := DiscoverEndpoints(ctx, srv.URL, []string{host}, DiscoveryConfig{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	gotPaths := map[string]bool{}
	for _, ep := range endpoints {
		gotPaths[ep.Path] = true
	}
	for _, want := range []string{"/login", "/dashboard"} {
		if !gotPaths[want] {
			t.Errorf("missing crawled path %q (got %v)", want, gotPaths)
		}
	}
	if gotPaths["/skip"] {
		t.Error("external host link leaked into endpoints")
	}
}

func TestDiscoverEndpoints_BoundedByMaxEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		var sb strings.Builder
		sb.WriteString(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
		for i := 0; i < 200; i++ {
			sb.WriteString("<url><loc>http://" + r.Host + "/page-")
			sb.WriteString(strings.Repeat("a", 1))
			sb.WriteString(string(rune('a' + i%26)))
			sb.WriteString(string(rune('0' + (i/26)%10)))
			sb.WriteString("</loc></url>")
		}
		sb.WriteString(`</urlset>`)
		w.Write([]byte(sb.String()))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	endpoints, err := DiscoverEndpoints(ctx, srv.URL, []string{host}, DiscoveryConfig{MaxEndpoints: 25})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(endpoints) > 25 {
		t.Errorf("expected at most 25 endpoints, got %d", len(endpoints))
	}
}

func TestDiscoverEndpoints_AlwaysProbesRoot(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	host := strings.TrimPrefix(srv.URL, "http://")
	endpoints, err := DiscoverEndpoints(ctx, srv.URL, []string{host}, DiscoveryConfig{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	hasRoot := false
	for _, ep := range endpoints {
		if ep.Path == "/" && ep.Method == "GET" {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		t.Errorf("expected root endpoint GET / (got %d endpoints)", len(endpoints))
	}
}
