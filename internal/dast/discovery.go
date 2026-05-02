package dast

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// DiscoveryConfig bounds endpoint discovery so a runaway crawl can't
// monopolize the worker. Zero values fall back to enterprise-safe defaults.
type DiscoveryConfig struct {
	MaxEndpoints int           // hard cap on endpoints returned (default 50)
	MaxDuration  time.Duration // overall discovery deadline (default 30s)
	HTTPClient   *http.Client  // override for tests; defaults to a 10s-timeout client
	UserAgent    string        // defaults to "SentinelCore-DAST/1.0"
}

// commonAPIPaths are well-known endpoints worth probing on every target so we
// surface obvious attack surface even when no spec / sitemap is published.
var commonAPIPaths = []string{
	"/health", "/healthz", "/api", "/api/v1", "/api/v2",
	"/login", "/admin", "/users", "/me", "/status", "/version",
	"/metrics", "/.env", "/.git/config",
}

// openAPIProbePaths are the canonical locations spec files publish at.
var openAPIProbePaths = []string{
	"/openapi.json", "/openapi.yaml",
	"/swagger.json", "/swagger.yaml",
	"/v3/api-docs", "/api-docs", "/api/swagger.json",
}

// DiscoverEndpoints performs lightweight endpoint discovery against a target,
// bounded by config. Sources, in order: OpenAPI/Swagger probes, sitemap.xml,
// robots.txt sitemap directive, 1-hop HTML link crawl from base URL, plus a
// small fixed list of well-known API paths. Endpoints are scoped to
// allowedHosts — anything off-host is dropped silently.
func DiscoverEndpoints(
	ctx context.Context,
	baseURL string,
	allowedHosts []string,
	cfg DiscoveryConfig,
) ([]Endpoint, error) {
	if cfg.MaxEndpoints <= 0 {
		cfg.MaxEndpoints = 50
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "SentinelCore-DAST/1.0"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("discovery: invalid base URL: %w", err)
	}
	allowed := normalizeHosts(allowedHosts, parsedBase.Host)

	dctx, cancel := context.WithTimeout(ctx, cfg.MaxDuration)
	defer cancel()

	c := &collector{
		base:    parsedBase,
		allowed: allowed,
		max:     cfg.MaxEndpoints,
		seen:    make(map[string]struct{}),
	}

	// Always probe the root so we don't return an empty surface for plain
	// targets that have no spec/sitemap/links worth crawling.
	c.add(Endpoint{Path: "/", Method: "GET", BaseURL: baseURL})

	d := &discoverer{cfg: cfg, base: parsedBase}

	// 1) OpenAPI / Swagger probes.
	for _, path := range openAPIProbePaths {
		if c.full() {
			break
		}
		if err := dctx.Err(); err != nil {
			break
		}
		if eps, ok := d.tryOpenAPI(dctx, path); ok {
			for _, ep := range eps {
				ep.BaseURL = baseURL
				c.add(ep)
			}
		}
	}

	// 2) Sitemap.xml at root.
	if !c.full() && dctx.Err() == nil {
		if eps, ok := d.trySitemap(dctx, "/sitemap.xml"); ok {
			for _, ep := range eps {
				if c.inScope(ep.absoluteURL()) {
					ep.BaseURL = baseURL
					c.add(ep)
				}
			}
		}
	}

	// 3) robots.txt sitemap: directive (may point elsewhere on host).
	if !c.full() && dctx.Err() == nil {
		for _, sitemapURL := range d.tryRobots(dctx) {
			if c.full() || dctx.Err() != nil {
				break
			}
			parsed, err := url.Parse(sitemapURL)
			if err != nil {
				continue
			}
			if !c.inScope(parsed.String()) {
				continue
			}
			if eps, ok := d.fetchSitemap(dctx, sitemapURL); ok {
				for _, ep := range eps {
					if c.inScope(ep.absoluteURL()) {
						ep.BaseURL = baseURL
						c.add(ep)
					}
				}
			}
		}
	}

	// 4) 1-hop HTML link crawl from base URL.
	if !c.full() && dctx.Err() == nil {
		for _, ep := range d.tryHTMLCrawl(dctx, baseURL) {
			if c.inScope(ep.absoluteURL()) {
				ep.BaseURL = baseURL
				c.add(ep)
			}
		}
	}

	// 5) Common API paths (always cheap, bounded by max).
	if !c.full() && dctx.Err() == nil {
		for _, p := range commonAPIPaths {
			if c.full() {
				break
			}
			c.add(Endpoint{Path: p, Method: "GET", BaseURL: baseURL})
		}
	}

	return c.endpoints(), nil
}

// collector tracks discovered endpoints, dedups, scopes, and bounds count.
type collector struct {
	mu      sync.Mutex
	base    *url.URL
	allowed map[string]struct{}
	max     int
	seen    map[string]struct{}
	out     []Endpoint
}

func (c *collector) full() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.out) >= c.max
}

func (c *collector) add(ep Endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.out) >= c.max {
		return
	}
	key := strings.ToUpper(ep.Method) + " " + ep.Path
	if _, ok := c.seen[key]; ok {
		return
	}
	c.seen[key] = struct{}{}
	c.out = append(c.out, ep)
}

func (c *collector) endpoints() []Endpoint {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]Endpoint, len(c.out))
	copy(cp, c.out)
	return cp
}

func (c *collector) inScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		// Relative URL — by definition same host.
		return true
	}
	_, ok := c.allowed[host]
	return ok
}

func normalizeHosts(allowed []string, fallback string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, h := range allowed {
		// Strip optional port from "host:port" forms.
		hostOnly := strings.ToLower(h)
		if idx := strings.Index(hostOnly, ":"); idx >= 0 {
			hostOnly = hostOnly[:idx]
		}
		if hostOnly != "" {
			m[hostOnly] = struct{}{}
		}
	}
	if len(m) == 0 && fallback != "" {
		hostOnly := strings.ToLower(fallback)
		if idx := strings.Index(hostOnly, ":"); idx >= 0 {
			hostOnly = hostOnly[:idx]
		}
		m[hostOnly] = struct{}{}
	}
	return m
}

func (e Endpoint) absoluteURL() string {
	if e.BaseURL == "" {
		return e.Path
	}
	return strings.TrimRight(e.BaseURL, "/") + e.Path
}

// discoverer wraps the per-source HTTP fetchers behind a single client.
type discoverer struct {
	cfg  DiscoveryConfig
	base *url.URL
}

func (d *discoverer) get(ctx context.Context, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", d.cfg.UserAgent)
	req.Header.Set("Accept", "application/json, application/xml, text/html, */*")
	return d.cfg.HTTPClient.Do(req)
}

// openAPIDoc captures the slice of an OpenAPI 3.x / Swagger 2.x doc we care
// about. We only need paths + method + parameter names.
type openAPIDoc struct {
	OpenAPI string                            `json:"openapi"`
	Swagger string                            `json:"swagger"`
	Paths   map[string]map[string]operation   `json:"paths"`
}

type operation struct {
	Parameters  []openAPIParam   `json:"parameters"`
	RequestBody *requestBody     `json:"requestBody"`
}

type openAPIParam struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Schema   struct {
		Type string `json:"type"`
	} `json:"schema"`
}

type requestBody struct {
	Content map[string]struct {
		Schema struct {
			Properties map[string]struct {
				Type string `json:"type"`
			} `json:"properties"`
		} `json:"schema"`
	} `json:"content"`
}

func (d *discoverer) tryOpenAPI(ctx context.Context, path string) ([]Endpoint, bool) {
	resp, err := d.get(ctx, d.base.ResolveReference(&url.URL{Path: path}).String())
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, false
	}

	var doc openAPIDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		// YAML support intentionally omitted — JSON is the universal form.
		return nil, false
	}
	if doc.OpenAPI == "" && doc.Swagger == "" {
		return nil, false
	}

	var out []Endpoint
	for p, ops := range doc.Paths {
		for method, op := range ops {
			methodUpper := strings.ToUpper(method)
			if !validHTTPMethod(methodUpper) {
				continue
			}
			ep := Endpoint{Path: p, Method: methodUpper}
			for _, prm := range op.Parameters {
				ep.Parameters = append(ep.Parameters, Parameter{
					Name:     prm.Name,
					In:       prm.In,
					Type:     prm.Schema.Type,
					Required: prm.Required,
				})
			}
			if op.RequestBody != nil {
				for ct, body := range op.RequestBody.Content {
					schema := map[string]string{}
					for name, prop := range body.Schema.Properties {
						schema[name] = prop.Type
					}
					ep.RequestBody = &RequestBodySpec{
						ContentType: ct,
						Schema:      schema,
					}
					break
				}
			}
			out = append(out, ep)
		}
	}
	return out, true
}

// trySitemap fetches /sitemap.xml at base and parses URLs.
func (d *discoverer) trySitemap(ctx context.Context, path string) ([]Endpoint, bool) {
	return d.fetchSitemap(ctx, d.base.ResolveReference(&url.URL{Path: path}).String())
}

func (d *discoverer) fetchSitemap(ctx context.Context, sitemapURL string) ([]Endpoint, bool) {
	resp, err := d.get(ctx, sitemapURL)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, false
	}

	var sm struct {
		URLs []struct {
			Loc string `xml:"loc"`
		} `xml:"url"`
	}
	if err := xml.Unmarshal(body, &sm); err != nil {
		return nil, false
	}

	var out []Endpoint
	for _, e := range sm.URLs {
		u, err := url.Parse(e.Loc)
		if err != nil || u.Path == "" {
			continue
		}
		// Stash absolute URL on BaseURL so the caller's scope check sees the
		// original host, not just the path resolved against the scan base.
		ep := Endpoint{Path: u.Path, Method: "GET"}
		if u.IsAbs() {
			ep.BaseURL = u.Scheme + "://" + u.Host
		}
		out = append(out, ep)
	}
	return out, true
}

func (d *discoverer) tryRobots(ctx context.Context) []string {
	resp, err := d.get(ctx, d.base.ResolveReference(&url.URL{Path: "/robots.txt"}).String())
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var out []string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 256*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Case-insensitive "Sitemap:" directive per RFC.
		if len(line) > 8 && strings.EqualFold(line[:8], "Sitemap:") {
			out = append(out, strings.TrimSpace(line[8:]))
		}
	}
	return out
}

func (d *discoverer) tryHTMLCrawl(ctx context.Context, pageURL string) []Endpoint {
	resp, err := d.get(ctx, pageURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") {
		return nil
	}

	doc, err := html.Parse(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}

	var out []Endpoint
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "a" || n.Data == "link") {
			for _, attr := range n.Attr {
				if attr.Key != "href" {
					continue
				}
				href := strings.TrimSpace(attr.Val)
				if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
					continue
				}
				resolved, err := d.base.Parse(href)
				if err != nil {
					continue
				}
				path := resolved.Path
				if path == "" {
					path = "/"
				}
				out = append(out, Endpoint{Path: path, Method: "GET", BaseURL: resolved.Scheme + "://" + resolved.Host})
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(doc)
	return out
}

func validHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD":
		return true
	}
	return false
}
