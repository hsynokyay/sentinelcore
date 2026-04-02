package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// SurfaceType classifies what kind of attack surface entry this is.
type SurfaceType string

const (
	SurfaceRoute     SurfaceType = "route"       // navigable URL
	SurfaceForm      SurfaceType = "form"        // HTML form
	SurfaceEndpoint  SurfaceType = "api_endpoint" // API endpoint from DAST
	SurfaceClickable SurfaceType = "clickable"   // interactive element
)

// ExposureLevel classifies how accessible a surface entry is.
type ExposureLevel string

const (
	ExposurePublic        ExposureLevel = "public"         // accessible anonymously
	ExposureAuthenticated ExposureLevel = "authenticated"  // requires authentication
	ExposureBoth          ExposureLevel = "both"           // accessible in both states
	ExposureUnknown       ExposureLevel = "unknown"        // no auth comparison done
)

// SurfaceEntry is a single item in the attack surface inventory.
type SurfaceEntry struct {
	ID            string        `json:"id"`             // deterministic fingerprint
	ProjectID     string        `json:"project_id"`
	ScanJobID     string        `json:"scan_job_id"`
	Type          SurfaceType   `json:"type"`
	URL           string        `json:"url"`            // normalized URL
	Method        string        `json:"method"`         // HTTP method (GET, POST, etc.)
	Exposure      ExposureLevel `json:"exposure"`
	Title         string        `json:"title,omitempty"`
	Metadata      EntryMetadata `json:"metadata"`
	FirstSeenAt   time.Time     `json:"first_seen_at"`
	LastSeenAt    time.Time     `json:"last_seen_at"`
	ScanCount     int           `json:"scan_count"`
	FindingIDs    []string      `json:"finding_ids,omitempty"`  // associated finding fingerprints
	ObservationCount int        `json:"observation_count"`
}

// EntryMetadata holds type-specific details for a surface entry.
type EntryMetadata struct {
	// Route metadata
	Depth     int    `json:"depth,omitempty"`
	PageTitle string `json:"page_title,omitempty"`

	// Form metadata
	FormAction string      `json:"form_action,omitempty"`
	FormMethod string      `json:"form_method,omitempty"`
	FieldCount int         `json:"field_count,omitempty"`
	HasCSRF    bool        `json:"has_csrf,omitempty"`
	IsSafe     bool        `json:"is_safe,omitempty"`
	Fields     []FormField `json:"fields,omitempty"`

	// Clickable metadata
	ElementTag  string `json:"element_tag,omitempty"`
	ElementText string `json:"element_text,omitempty"`
	ElementRole string `json:"element_role,omitempty"`
	Safety      string `json:"safety,omitempty"` // safe/unsafe/unknown

	// API endpoint metadata
	ContentType string   `json:"content_type,omitempty"`
	Parameters  []string `json:"parameters,omitempty"`
}

// SurfaceInventory is the complete attack surface inventory for a scan.
type SurfaceInventory struct {
	ProjectID  string                    `json:"project_id"`
	ScanJobID  string                    `json:"scan_job_id"`
	Entries    map[string]*SurfaceEntry  `json:"entries"` // fingerprint → entry
	Stats      InventoryStats            `json:"stats"`
	BuiltAt    time.Time                 `json:"built_at"`
}

// InventoryStats summarizes the inventory contents.
type InventoryStats struct {
	TotalEntries      int            `json:"total_entries"`
	ByType            map[string]int `json:"by_type"`
	ByExposure        map[string]int `json:"by_exposure"`
	RoutesWithForms   int            `json:"routes_with_forms"`
	UnsafeClickables  int            `json:"unsafe_clickables"`
	EntriesWithFindings int          `json:"entries_with_findings"`
}

// NewSurfaceInventory creates an empty inventory.
func NewSurfaceInventory(projectID, scanJobID string) *SurfaceInventory {
	return &SurfaceInventory{
		ProjectID: projectID,
		ScanJobID: scanJobID,
		Entries:   make(map[string]*SurfaceEntry),
		BuiltAt:   time.Now(),
	}
}

// AddEntry adds or updates a surface entry in the inventory.
// If an entry with the same fingerprint exists, it updates LastSeenAt and ScanCount.
func (inv *SurfaceInventory) AddEntry(entry *SurfaceEntry) {
	if existing, ok := inv.Entries[entry.ID]; ok {
		existing.LastSeenAt = entry.LastSeenAt
		existing.ScanCount++
		if entry.Exposure != ExposureUnknown && existing.Exposure == ExposureUnknown {
			existing.Exposure = entry.Exposure
		}
		for _, fid := range entry.FindingIDs {
			existing.FindingIDs = appendUnique(existing.FindingIDs, fid)
		}
		existing.ObservationCount += entry.ObservationCount
		return
	}
	entry.ScanCount = 1
	inv.Entries[entry.ID] = entry
}

// ComputeStats calculates summary statistics.
func (inv *SurfaceInventory) ComputeStats() {
	stats := InventoryStats{
		ByType:     make(map[string]int),
		ByExposure: make(map[string]int),
	}
	for _, e := range inv.Entries {
		stats.TotalEntries++
		stats.ByType[string(e.Type)]++
		stats.ByExposure[string(e.Exposure)]++
		if e.Type == SurfaceRoute && e.Metadata.FieldCount > 0 {
			stats.RoutesWithForms++
		}
		if e.Type == SurfaceClickable && e.Metadata.Safety == "unsafe" {
			stats.UnsafeClickables++
		}
		if len(e.FindingIDs) > 0 {
			stats.EntriesWithFindings++
		}
	}
	inv.Stats = stats
}

// QueryByType returns entries matching the given surface type.
func (inv *SurfaceInventory) QueryByType(t SurfaceType) []*SurfaceEntry {
	var results []*SurfaceEntry
	for _, e := range inv.Entries {
		if e.Type == t {
			results = append(results, e)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	return results
}

// QueryByExposure returns entries matching the given exposure level.
func (inv *SurfaceInventory) QueryByExposure(level ExposureLevel) []*SurfaceEntry {
	var results []*SurfaceEntry
	for _, e := range inv.Entries {
		if e.Exposure == level {
			results = append(results, e)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	return results
}

// QueryWithFindings returns entries that have associated findings.
func (inv *SurfaceInventory) QueryWithFindings() []*SurfaceEntry {
	var results []*SurfaceEntry
	for _, e := range inv.Entries {
		if len(e.FindingIDs) > 0 {
			results = append(results, e)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].URL < results[j].URL })
	return results
}

// SurfaceFingerprint generates a deterministic ID for a surface entry.
func SurfaceFingerprint(surfaceType SurfaceType, url, method string) string {
	h := sha256.New()
	h.Write([]byte(string(surfaceType)))
	h.Write([]byte("|"))
	h.Write([]byte(NormalizeURL(url)))
	h.Write([]byte("|"))
	h.Write([]byte(strings.ToUpper(method)))
	return hex.EncodeToString(h.Sum(nil))[:16] // 16 hex chars = 64-bit, collision-resistant for inventory
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
