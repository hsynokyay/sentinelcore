package browser

// AuthState labels which authentication context a crawl was performed under.
type AuthState string

const (
	AuthStateAnonymous     AuthState = "anonymous"
	AuthStateAuthenticated AuthState = "authenticated"
)

// CrawlSnapshot captures the surface area discovered during a single crawl pass.
// This is a reduced representation of []PageResult suitable for comparison.
type CrawlSnapshot struct {
	State       AuthState         `json:"state"`
	URLs        map[string]bool   `json:"urls"`          // normalized URLs visited
	Forms       map[string]FormSummary `json:"forms"`    // URL → form summary
	ClickCount  int               `json:"click_count"`
	PageCount   int               `json:"page_count"`
}

// FormSummary is a per-URL summary of discovered forms.
type FormSummary struct {
	Count    int      `json:"count"`
	Actions  []string `json:"actions"`
	Methods  []string `json:"methods"`
	HasCSRF  bool     `json:"has_csrf"` // true if ANY form on page has CSRF
}

// SnapshotFromPages builds a CrawlSnapshot from crawl results.
func SnapshotFromPages(state AuthState, pages []PageResult) *CrawlSnapshot {
	snap := &CrawlSnapshot{
		State: state,
		URLs:  make(map[string]bool),
		Forms: make(map[string]FormSummary),
	}

	for _, page := range pages {
		if page.Error != "" {
			continue
		}
		normalized := NormalizeURL(page.URL)
		if normalized == "" {
			continue
		}
		snap.URLs[normalized] = true
		snap.PageCount++
		snap.ClickCount += len(page.Interactions)

		if len(page.Forms) > 0 {
			fs := FormSummary{Count: len(page.Forms)}
			for _, f := range page.Forms {
				fs.Actions = append(fs.Actions, f.Action)
				fs.Methods = append(fs.Methods, f.Method)
				if f.HasCSRF {
					fs.HasCSRF = true
				}
			}
			snap.Forms[normalized] = fs
		}
	}

	return snap
}

// AuthStateVariance captures differences between anonymous and authenticated crawls.
type AuthStateVariance struct {
	// URLs only reachable when authenticated (protected content)
	AuthOnlyURLs []string `json:"auth_only_urls"`

	// URLs only reachable anonymously (should not happen — indicates potential issue)
	AnonOnlyURLs []string `json:"anon_only_urls"`

	// Forms that appear only when authenticated
	AuthOnlyForms map[string]FormSummary `json:"auth_only_forms"`

	// Forms that appear only anonymously (unusual — may indicate auth bypass)
	AnonOnlyForms map[string]FormSummary `json:"anon_only_forms"`

	// URLs reachable in both states (shared surface)
	SharedURLs []string `json:"shared_urls"`

	// Summary stats
	AnonPageCount int `json:"anon_page_count"`
	AuthPageCount int `json:"auth_page_count"`
}

// ComputeVariance compares two crawl snapshots and identifies differences.
func ComputeVariance(anon, auth *CrawlSnapshot) *AuthStateVariance {
	v := &AuthStateVariance{
		AuthOnlyForms: make(map[string]FormSummary),
		AnonOnlyForms: make(map[string]FormSummary),
		AnonPageCount: anon.PageCount,
		AuthPageCount: auth.PageCount,
	}

	// URL diff
	for url := range auth.URLs {
		if anon.URLs[url] {
			v.SharedURLs = append(v.SharedURLs, url)
		} else {
			v.AuthOnlyURLs = append(v.AuthOnlyURLs, url)
		}
	}
	for url := range anon.URLs {
		if !auth.URLs[url] {
			v.AnonOnlyURLs = append(v.AnonOnlyURLs, url)
		}
	}

	// Form diff
	for url, fs := range auth.Forms {
		if _, exists := anon.Forms[url]; !exists {
			v.AuthOnlyForms[url] = fs
		}
	}
	for url, fs := range anon.Forms {
		if _, exists := auth.Forms[url]; !exists {
			v.AnonOnlyForms[url] = fs
		}
	}

	return v
}
