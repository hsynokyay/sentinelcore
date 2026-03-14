package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Service provides HTTP endpoints for the Vulnerability Intelligence API.
type Service struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// NewService creates a new vulnerability intelligence service.
func NewService(pool *pgxpool.Pool, logger zerolog.Logger) *Service {
	return &Service{pool: pool, logger: logger}
}

// RegisterRoutes registers HTTP handlers on the given ServeMux.
func (s *Service) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/vulns/lookup", s.handleLookup)
	mux.HandleFunc("GET /api/v1/vulns/cve/{cve_id}", s.handleGetCVE)
	mux.HandleFunc("GET /api/v1/vulns/feed-status", s.handleFeedStatus)
	mux.HandleFunc("POST /api/v1/vulns/import", s.handleImport)
	mux.HandleFunc("GET /healthz", s.handleHealth)
}

// handleLookup queries for vulnerabilities matching a specific package version.
// GET /api/v1/vulns/lookup?ecosystem=npm&name=lodash&version=4.17.20
func (s *Service) handleLookup(w http.ResponseWriter, r *http.Request) {
	ecosystem := r.URL.Query().Get("ecosystem")
	name := r.URL.Query().Get("name")
	version := r.URL.Query().Get("version")

	if ecosystem == "" || name == "" || version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "ecosystem, name, and version query parameters are required",
		})
		return
	}

	rows, err := s.pool.Query(r.Context(), `
		SELECT v.cve_id, v.source, v.title, v.description,
		       v.cvss_v31_score, v.cvss_v31_vector, v.cwe_ids,
		       v.exploit_available, v.actively_exploited,
		       pv.version_range, pv.fixed_version
		FROM vuln_intel.vulnerabilities v
		JOIN vuln_intel.package_vulnerabilities pv ON pv.vulnerability_id = v.id
		WHERE pv.ecosystem = $1 AND pv.package_name = $2
	`, strings.ToLower(ecosystem), name)
	if err != nil {
		s.logger.Error().Err(err).Msg("lookup query failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	defer rows.Close()

	type LookupResult struct {
		CVEID             string  `json:"cve_id"`
		Source            string  `json:"source"`
		Title             string  `json:"title"`
		Description       string  `json:"description"`
		CVSSv31Score      float64 `json:"cvss_v31_score"`
		CVSSv31Vector     string  `json:"cvss_v31_vector"`
		CWEIDs            []int   `json:"cwe_ids"`
		ExploitAvailable  bool    `json:"exploit_available"`
		ActivelyExploited bool    `json:"actively_exploited"`
		VersionRange      string  `json:"version_range"`
		FixedVersion      string  `json:"fixed_version"`
	}

	var results []LookupResult
	for rows.Next() {
		var lr LookupResult
		if err := rows.Scan(
			&lr.CVEID, &lr.Source, &lr.Title, &lr.Description,
			&lr.CVSSv31Score, &lr.CVSSv31Vector, &lr.CWEIDs,
			&lr.ExploitAvailable, &lr.ActivelyExploited,
			&lr.VersionRange, &lr.FixedVersion,
		); err != nil {
			s.logger.Error().Err(err).Msg("scan row failed")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}

		// Filter by version match
		if MatchVersion(version, lr.VersionRange, ecosystem) {
			results = append(results, lr)
		}
	}

	if results == nil {
		results = []LookupResult{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ecosystem": ecosystem,
		"package":   name,
		"version":   version,
		"vulns":     results,
		"count":     len(results),
	})
}

// handleGetCVE returns details for a specific CVE.
// GET /api/v1/vulns/cve/{cve_id}
func (s *Service) handleGetCVE(w http.ResponseWriter, r *http.Request) {
	cveID := r.PathValue("cve_id")
	if cveID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cve_id is required"})
		return
	}

	var v NormalizedVuln
	var cweIDs []int

	err := s.pool.QueryRow(r.Context(), `
		SELECT cve_id, source, title, description,
		       cvss_v31_score, cvss_v31_vector, cwe_ids,
		       exploit_available, actively_exploited,
		       published_at, modified_at
		FROM vuln_intel.vulnerabilities
		WHERE cve_id = $1
	`, cveID).Scan(
		&v.CVEID, &v.Source, &v.Title, &v.Description,
		&v.CVSSv31Score, &v.CVSSv31Vector, &cweIDs,
		&v.ExploitAvailable, &v.ActivelyExploited,
		&v.PublishedAt, &v.ModifiedAt,
	)
	if err == pgx.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "CVE not found"})
		return
	}
	if err != nil {
		s.logger.Error().Err(err).Str("cve_id", cveID).Msg("get CVE failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	v.CWEIDs = cweIDs

	// Fetch affected packages
	pkgRows, err := s.pool.Query(r.Context(), `
		SELECT pv.ecosystem, pv.package_name, pv.version_range, pv.fixed_version
		FROM vuln_intel.package_vulnerabilities pv
		JOIN vuln_intel.vulnerabilities v ON v.id = pv.vulnerability_id
		WHERE v.cve_id = $1
	`, cveID)
	if err == nil {
		defer pkgRows.Close()
		for pkgRows.Next() {
			var ap AffectedPackage
			if scanErr := pkgRows.Scan(&ap.Ecosystem, &ap.PackageName, &ap.VersionRange, &ap.FixedVersion); scanErr == nil {
				v.AffectedPackages = append(v.AffectedPackages, ap)
			}
		}
	}

	writeJSON(w, http.StatusOK, v)
}

// handleFeedStatus returns the sync status of all configured feeds.
// GET /api/v1/vulns/feed-status
func (s *Service) handleFeedStatus(w http.ResponseWriter, r *http.Request) {
	rows, err := s.pool.Query(r.Context(), `
		SELECT feed_name, last_sync_at, records_synced,
		       last_error, created_at, updated_at
		FROM vuln_intel.feed_sync_status
		ORDER BY feed_name
	`)
	if err != nil {
		s.logger.Error().Err(err).Msg("feed status query failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	defer rows.Close()

	type FeedStatus struct {
		FeedName      string  `json:"feed_name"`
		LastSyncAt    *string `json:"last_sync_at"`
		RecordsSynced int     `json:"records_synced"`
		LastError     *string `json:"last_error"`
		CreatedAt     string  `json:"created_at"`
		UpdatedAt     string  `json:"updated_at"`
	}

	var feeds []FeedStatus
	for rows.Next() {
		var fs FeedStatus
		if err := rows.Scan(
			&fs.FeedName, &fs.LastSyncAt, &fs.RecordsSynced,
			&fs.LastError, &fs.CreatedAt, &fs.UpdatedAt,
		); err != nil {
			s.logger.Error().Err(err).Msg("scan feed status failed")
			continue
		}
		feeds = append(feeds, fs)
	}

	if feeds == nil {
		feeds = []FeedStatus{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"feeds": feeds,
		"count": len(feeds),
	})
}

// ImportRequest is the expected body for POST /api/v1/vulns/import.
type ImportRequest struct {
	Vulns []NormalizedVuln `json:"vulns"`
}

// handleImport imports normalized vulnerability records.
// POST /api/v1/vulns/import
func (s *Service) handleImport(w http.ResponseWriter, r *http.Request) {
	var req ImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid JSON: %v", err),
		})
		return
	}

	if len(req.Vulns) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no vulnerabilities provided"})
		return
	}

	ctx := r.Context()
	imported := 0

	for _, nv := range req.Vulns {
		if err := s.upsertVuln(ctx, nv); err != nil {
			s.logger.Error().Err(err).Str("cve_id", nv.CVEID).Msg("import failed")
			continue
		}
		imported++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"imported": imported,
		"total":    len(req.Vulns),
	})
}

// upsertVuln inserts or updates a vulnerability and its package mappings.
func (s *Service) upsertVuln(ctx context.Context, nv NormalizedVuln) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var vulnID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO vuln_intel.vulnerabilities (
			cve_id, source, title, description,
			cvss_v31_score, cvss_v31_vector, cwe_ids,
			exploit_available, actively_exploited,
			published_at, modified_at, raw_data,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)
		ON CONFLICT (cve_id) DO UPDATE SET
			source = EXCLUDED.source,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			cvss_v31_score = EXCLUDED.cvss_v31_score,
			cvss_v31_vector = EXCLUDED.cvss_v31_vector,
			cwe_ids = EXCLUDED.cwe_ids,
			exploit_available = EXCLUDED.exploit_available,
			actively_exploited = EXCLUDED.actively_exploited,
			modified_at = EXCLUDED.modified_at,
			raw_data = EXCLUDED.raw_data,
			updated_at = EXCLUDED.updated_at
		RETURNING id
	`, nv.CVEID, nv.Source, nv.Title, nv.Description,
		nv.CVSSv31Score, nv.CVSSv31Vector, nv.CWEIDs,
		nv.ExploitAvailable, nv.ActivelyExploited,
		parseTimeOrNil(nv.PublishedAt), parseTimeOrNil(nv.ModifiedAt),
		nv.RawData, time.Now().UTC(),
	).Scan(&vulnID)
	if err != nil {
		return fmt.Errorf("upsert vulnerability: %w", err)
	}

	// Delete existing package mappings and re-insert
	if _, err := tx.Exec(ctx, `
		DELETE FROM vuln_intel.package_vulnerabilities WHERE vulnerability_id = $1
	`, vulnID); err != nil {
		return fmt.Errorf("delete package vulns: %w", err)
	}

	for _, ap := range nv.AffectedPackages {
		if _, err := tx.Exec(ctx, `
			INSERT INTO vuln_intel.package_vulnerabilities (
				vulnerability_id, ecosystem, package_name,
				version_range, fixed_version, created_at
			) VALUES ($1, $2, $3, $4, $5, $6)
		`, vulnID, ap.Ecosystem, ap.PackageName,
			ap.VersionRange, ap.FixedVersion, time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("insert package vuln: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// parseTimeOrNil attempts to parse an ISO8601 timestamp, returning nil on failure.
func parseTimeOrNil(s string) *time.Time {
	if s == "" {
		return nil
	}
	// Try common ISO8601 formats
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05.000",
		time.RFC3339Nano,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// handleHealth returns a simple health check.
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.pool.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
