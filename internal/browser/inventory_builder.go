package browser

import (
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast"
)

// BuildInventory constructs a SurfaceInventory from browser crawl results,
// auth-state variance data, and findings.
func BuildInventory(
	projectID, scanJobID string,
	pages []PageResult,
	variance *AuthStateVariance,
	findings []dast.Finding,
) *SurfaceInventory {
	inv := NewSurfaceInventory(projectID, scanJobID)
	now := time.Now()

	// Build exposure lookup from variance data.
	exposureLookup := buildExposureLookup(variance)

	// Index findings by URL for association.
	findingsByURL := indexFindingsByURL(findings)

	// Process each crawled page.
	for _, page := range pages {
		if page.Error != "" {
			continue
		}
		normalized := NormalizeURL(page.URL)
		if normalized == "" {
			continue
		}

		// Route entry.
		routeID := SurfaceFingerprint(SurfaceRoute, page.URL, "GET")
		exposure := exposureForURL(normalized, exposureLookup)
		routeEntry := &SurfaceEntry{
			ID:          routeID,
			ProjectID:   projectID,
			ScanJobID:   scanJobID,
			Type:        SurfaceRoute,
			URL:         normalized,
			Method:      "GET",
			Exposure:    exposure,
			Title:       page.Title,
			Metadata: EntryMetadata{
				Depth:     page.Depth,
				PageTitle: page.Title,
			},
			FirstSeenAt: now,
			LastSeenAt:  now,
			FindingIDs:  findingsByURL[normalized],
		}
		inv.AddEntry(routeEntry)

		// Form entries.
		for _, form := range page.Forms {
			formURL := form.Action
			if formURL == "" {
				formURL = page.URL
			}
			formNorm := NormalizeURL(ResolveURL(formURL, page.URL))
			if formNorm == "" {
				formNorm = normalized
			}
			formID := SurfaceFingerprint(SurfaceForm, formNorm, form.Method)
			formEntry := &SurfaceEntry{
				ID:        formID,
				ProjectID: projectID,
				ScanJobID: scanJobID,
				Type:      SurfaceForm,
				URL:       formNorm,
				Method:    form.Method,
				Exposure:  exposure,
				Metadata: EntryMetadata{
					FormAction: form.Action,
					FormMethod: form.Method,
					FieldCount: len(form.Fields),
					HasCSRF:    form.HasCSRF,
					IsSafe:     form.IsSafe,
					Fields:     form.Fields,
				},
				FirstSeenAt: now,
				LastSeenAt:  now,
				FindingIDs:  findingsByURL[formNorm],
			}
			inv.AddEntry(formEntry)
		}

		// Clickable entries (only unsafe/unknown — safe are expected navigation).
		for _, ct := range page.ClickTargets {
			if ct.Safety == ClickSafe {
				continue // safe clickables are normal navigation, not attack surface
			}
			clickURL := page.URL
			if ct.Href != "" {
				resolved := NormalizeURL(ResolveURL(ct.Href, page.URL))
				if resolved != "" {
					clickURL = resolved
				}
			}
			clickID := SurfaceFingerprint(SurfaceClickable, clickURL, ct.Tag+"-"+ct.Text)
			clickEntry := &SurfaceEntry{
				ID:        clickID,
				ProjectID: projectID,
				ScanJobID: scanJobID,
				Type:      SurfaceClickable,
				URL:       NormalizeURL(clickURL),
				Method:    "CLICK",
				Exposure:  exposure,
				Metadata: EntryMetadata{
					ElementTag:  ct.Tag,
					ElementText: ct.Text,
					ElementRole: ct.Role,
					Safety:      ct.Safety.String(),
				},
				FirstSeenAt: now,
				LastSeenAt:  now,
			}
			inv.AddEntry(clickEntry)
		}
	}

	inv.ComputeStats()
	return inv
}

// buildExposureLookup creates a URL → ExposureLevel map from variance data.
func buildExposureLookup(variance *AuthStateVariance) map[string]ExposureLevel {
	lookup := make(map[string]ExposureLevel)
	if variance == nil {
		return lookup
	}
	for _, url := range variance.AuthOnlyURLs {
		lookup[url] = ExposureAuthenticated
	}
	for _, url := range variance.AnonOnlyURLs {
		lookup[url] = ExposurePublic
	}
	for _, url := range variance.SharedURLs {
		lookup[url] = ExposureBoth
	}
	return lookup
}

// exposureForURL returns the exposure level for a URL.
func exposureForURL(normalizedURL string, lookup map[string]ExposureLevel) ExposureLevel {
	if level, ok := lookup[normalizedURL]; ok {
		return level
	}
	return ExposureUnknown
}

// indexFindingsByURL builds a map of normalized URL → finding fingerprints.
func indexFindingsByURL(findings []dast.Finding) map[string][]string {
	idx := make(map[string][]string)
	for _, f := range findings {
		normalized := NormalizeURL(f.URL)
		if normalized == "" {
			continue
		}
		fp := ""
		if f.Evidence != nil {
			fp = f.Evidence.SHA256
		} else {
			fp = f.ID
		}
		idx[normalized] = appendUnique(idx[normalized], fp)
	}
	return idx
}
