package risk

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the persistence layer for the risk package. All PostgreSQL
// interactions go through this type so the correlator can be tested
// against a stub in unit tests and the real pool in integration tests.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a Store backed by the given pgx connection pool.
// Panics if pool is nil — the risk package requires a live database.
func NewStore(pool *pgxpool.Pool) *Store {
	if pool == nil {
		panic("risk: NewStore called with nil pool")
	}
	return &Store{pool: pool}
}

// ErrNotFound is returned by Store lookups when no row matches.
var ErrNotFound = errors.New("risk: not found")

// Ping verifies the database connection. Used by health checks and by
// later chunks as a cheap smoke test before beginning a correlation run.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// BeginTx starts a new transaction for a rebuild. Callers MUST either
// Commit or Rollback before returning.
func (s *Store) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

// Pool exposes the underlying pgx pool for code paths that need direct
// access (e.g. the worker's resolveProjectForScan lookup). Prefer the
// typed methods when possible.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// AcquireProjectLock takes a per-project advisory lock for the duration of
// the transaction. Released automatically on COMMIT or ROLLBACK. Blocks
// until the lock is available.
func (s *Store) AcquireProjectLock(ctx context.Context, tx pgx.Tx, projectID string) error {
	key := hashProjectLock(projectID)
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, key)
	return err
}

// hashProjectLock derives a stable int64 key for pg_advisory_xact_lock
// from a project UUID string. FNV-1a is used for speed and determinism.
func hashProjectLock(projectID string) int64 {
	h := fnv.New64a()
	h.Write([]byte("risk-correlation:"))
	h.Write([]byte(projectID))
	return int64(h.Sum64())
}

// CreateRun inserts a new row into risk.correlation_runs and returns its id.
func (s *Store) CreateRun(ctx context.Context, tx pgx.Tx, projectID, trigger string, triggeredByScan *string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO risk.correlation_runs (project_id, trigger, triggered_by_scan, status)
		VALUES ($1, $2, $3, 'running')
		RETURNING id
	`, projectID, trigger, triggeredByScan).Scan(&id)
	return id, err
}

// FinishRun marks a run as successful and records counters.
func (s *Store) FinishRun(ctx context.Context, tx pgx.Tx, runID string, r Run) error {
	_, err := tx.Exec(ctx, `
		UPDATE risk.correlation_runs SET
			finished_at = now(),
			status = 'ok',
			clusters_touched = $2,
			clusters_created = $3,
			clusters_resolved = $4,
			findings_processed = $5
		WHERE id = $1
	`, runID, r.ClustersTouched, r.ClustersCreated, r.ClustersResolved, r.FindingsProcessed)
	return err
}

// FailRun marks a run as errored. Called from the worker's error path.
func (s *Store) FailRun(ctx context.Context, tx pgx.Tx, runID, errMsg string) error {
	_, err := tx.Exec(ctx, `
		UPDATE risk.correlation_runs SET
			finished_at = now(),
			status = 'error',
			error_message = $2
		WHERE id = $1
	`, runID, errMsg)
	return err
}

// LoadActiveFindings returns every finding belonging to the project that
// should participate in correlation. "Active" means: not suppressed, not
// resolved. The risk correlator treats these as the authoritative set.
func (s *Store) LoadActiveFindings(ctx context.Context, tx pgx.Tx, projectID string) ([]*Finding, error) {
	rows, err := tx.Query(ctx, `
		SELECT
			id, project_id, scan_job_id, finding_type,
			COALESCE(rule_id, ''),
			title,
			COALESCE(cwe_id, 0),
			COALESCE(owasp_category, ''),
			severity, confidence,
			COALESCE(file_path, ''),
			COALESCE(line_start, 0),
			COALESCE(function_name, ''),
			COALESCE(url, ''),
			COALESCE(http_method, ''),
			COALESCE(parameter, '')
		FROM findings.findings
		WHERE project_id = $1
		  AND status NOT IN ('suppressed', 'resolved', 'false_positive')
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f := &Finding{}
		if err := rows.Scan(
			&f.ID, &f.ProjectID, &f.ScanJobID, &f.Type,
			&f.RuleID, &f.Title, &f.CWEID, &f.OWASPCategory,
			&f.Severity, &f.Confidence,
			&f.FilePath, &f.LineStart, &f.FunctionName,
			&f.URL, &f.HTTPMethod, &f.Parameter,
		); err != nil {
			return nil, err
		}
		f.Language = languageFromRuleID(f.RuleID)
		out = append(out, f)
	}
	return out, rows.Err()
}

// languageFromRuleID infers language from a rule ID like SC-JAVA-SQL-001.
// Returns empty string for DAST findings and any unrecognized prefix.
func languageFromRuleID(ruleID string) string {
	switch {
	case len(ruleID) >= 8 && ruleID[:8] == "SC-JAVA-":
		return "java"
	case len(ruleID) >= 6 && ruleID[:6] == "SC-JS-":
		return "javascript"
	case len(ruleID) >= 6 && ruleID[:6] == "SC-PY-":
		return "python"
	case len(ruleID) >= 10 && ruleID[:10] == "SC-CSHARP-":
		return "csharp"
	}
	return ""
}

// UpsertCluster atomically inserts or updates a cluster by fingerprint.
// Returns (clusterID, wasInserted).
//
// Auto-reactivation: auto_resolved clusters become active again on touch.
// muted clusters with expired muted_until become active.
// user_resolved clusters KEEP their status (never auto-reactivate).
func (s *Store) UpsertCluster(ctx context.Context, tx pgx.Tx, runID string, c *Cluster) (id string, inserted bool, err error) {
	err = tx.QueryRow(ctx, `
		INSERT INTO risk.clusters (
			project_id, fingerprint, fingerprint_version, fingerprint_kind,
			title, vuln_class, cwe_id, owasp_category, language,
			canonical_route, canonical_param, http_method,
			file_path, enclosing_method, location_group,
			severity, status, last_run_id, last_seen_at, first_seen_at,
			exposure
		)
		VALUES ($1, $2, $3, $4, $5, $6,
				NULLIF($7, 0),
				NULLIF($8, ''),
				NULLIF($9, ''),
				NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''),
				NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''),
				$16, 'active', $17, now(), now(),
				'unknown')
		ON CONFLICT (project_id, fingerprint_version, fingerprint) DO UPDATE SET
			title = EXCLUDED.title,
			severity = EXCLUDED.severity,
			last_seen_at = now(),
			last_run_id = EXCLUDED.last_run_id,
			missing_run_count = 0,
			status = CASE
				WHEN risk.clusters.status = 'auto_resolved' THEN 'active'
				WHEN risk.clusters.status = 'muted'
				     AND risk.clusters.muted_until IS NOT NULL
				     AND risk.clusters.muted_until < now() THEN 'active'
				ELSE risk.clusters.status
			END,
			resolved_at = CASE
				WHEN risk.clusters.status = 'auto_resolved' THEN NULL
				ELSE risk.clusters.resolved_at
			END
		RETURNING id, (xmax = 0) AS inserted
	`,
		c.ProjectID, c.Fingerprint, c.FingerprintVersion, c.FingerprintKind,
		c.Title, c.VulnClass, c.CWEID, c.OWASPCategory, c.Language,
		c.CanonicalRoute, c.CanonicalParam, c.HTTPMethod,
		c.FilePath, c.EnclosingMethod, c.LocationGroup,
		c.Severity, runID,
	).Scan(&id, &inserted)
	return
}

// UpsertClusterFinding attaches a finding to a cluster for the current run.
// Idempotent within a run — repeated calls refresh last_seen_run_id.
func (s *Store) UpsertClusterFinding(ctx context.Context, tx pgx.Tx, clusterID, findingID, role, runID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO risk.cluster_findings
			(cluster_id, finding_id, role, first_seen_run_id, last_seen_run_id)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (cluster_id, finding_id) DO UPDATE SET
			last_seen_run_id = EXCLUDED.last_seen_run_id
	`, clusterID, findingID, role, runID)
	return err
}

// DeleteStaleClusterFindings removes any cluster_findings row in the project
// whose last_seen_run_id is not the current run. This handles findings that
// migrated between clusters and findings that were removed entirely.
func (s *Store) DeleteStaleClusterFindings(ctx context.Context, tx pgx.Tx, projectID, runID string) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM risk.cluster_findings cf
		USING risk.clusters c
		WHERE cf.cluster_id = c.id
		  AND c.project_id = $1
		  AND cf.last_seen_run_id <> $2
	`, projectID, runID)
	return err
}

// RecomputeClusterAggregates refreshes finding_count, surface_count,
// severity, and exposure for every touched cluster based on current
// cluster_findings and surface_entries. Runs inside the same transaction
// as the rebuild.
func (s *Store) RecomputeClusterAggregates(ctx context.Context, tx pgx.Tx, clusterIDs []string) error {
	if len(clusterIDs) == 0 {
		return nil
	}
	// finding_count + severity (take the worst across members)
	_, err := tx.Exec(ctx, `
		UPDATE risk.clusters c SET
			finding_count = sub.cnt,
			severity = COALESCE(sub.worst_sev, c.severity)
		FROM (
			SELECT
				cf.cluster_id,
				count(*) AS cnt,
				(ARRAY_AGG(f.severity ORDER BY
					CASE f.severity
						WHEN 'critical' THEN 5
						WHEN 'high'     THEN 4
						WHEN 'medium'   THEN 3
						WHEN 'low'      THEN 2
						WHEN 'info'     THEN 1
						ELSE 0
					END DESC))[1] AS worst_sev
			FROM risk.cluster_findings cf
			JOIN findings.findings f ON f.id = cf.finding_id
			WHERE cf.cluster_id = ANY($1)
			GROUP BY cf.cluster_id
		) sub
		WHERE c.id = sub.cluster_id
	`, clusterIDs)
	if err != nil {
		return err
	}

	// Zero out clusters whose cluster_findings were all cleaned up.
	_, err = tx.Exec(ctx, `
		UPDATE risk.clusters c SET finding_count = 0
		WHERE c.id = ANY($1)
		  AND NOT EXISTS (
		      SELECT 1 FROM risk.cluster_findings cf
		      WHERE cf.cluster_id = c.id
		  )
	`, clusterIDs)
	if err != nil {
		return err
	}

	// surface_count + exposure (worst across linked surface entries).
	// Surface linkage for DAST clusters is by exact canonical_route match on
	// the surface entry URL (lowercased, scheme+host stripped). SAST
	// clusters have no surface link in MVP — surface_count stays 0.
	_, err = tx.Exec(ctx, `
		UPDATE risk.clusters c SET
			surface_count = sub.cnt,
			exposure = sub.worst_exp
		FROM (
			SELECT
				c2.id AS cluster_id,
				count(s.id) AS cnt,
				COALESCE(
					(ARRAY_AGG(s.exposure ORDER BY
						CASE s.exposure
							WHEN 'public'        THEN 4
							WHEN 'both'          THEN 3
							WHEN 'authenticated' THEN 2
							WHEN 'unknown'       THEN 1
							ELSE 0
						END DESC))[1],
					'unknown'
				) AS worst_exp
			FROM risk.clusters c2
			LEFT JOIN scans.surface_entries s
			  ON s.project_id = c2.project_id
			 AND c2.fingerprint_kind = 'dast_route'
			 AND lower(regexp_replace(s.url, '^https?://[^/]+', '')) = c2.canonical_route
			WHERE c2.id = ANY($1)
			GROUP BY c2.id
		) sub
		WHERE c.id = sub.cluster_id
	`, clusterIDs)
	return err
}

// DeleteStaleEvidence removes old evidence rows for touched clusters so the
// next emission writes a fresh snapshot.
func (s *Store) DeleteStaleEvidence(ctx context.Context, tx pgx.Tx, clusterIDs []string, runID string) error {
	if len(clusterIDs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		DELETE FROM risk.cluster_evidence
		WHERE cluster_id = ANY($1) AND source_run_id <> $2
	`, clusterIDs, runID)
	return err
}

// InsertEvidence persists a single evidence row. Called once per evidence
// item emitted by the scorer or the surface-link logic.
func (s *Store) InsertEvidence(ctx context.Context, tx pgx.Tx, e *Evidence) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO risk.cluster_evidence
			(cluster_id, category, code, label, weight, ref_type, ref_id,
			 sort_order, source_run_id, metadata)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8, $9, COALESCE($10, '{}')::jsonb)
	`, e.ClusterID, e.Category, e.Code, e.Label, e.Weight, e.RefType, e.RefID,
		e.SortOrder, e.SourceRunID, metadataJSON(e.Metadata))
	return err
}

// metadataJSON marshals the metadata map into a tiny JSON object string.
// Only string-valued keys are preserved; richer types go through the
// caller's own marshalling.
func metadataJSON(m map[string]any) string {
	if m == nil {
		return "{}"
	}
	out := "{"
	first := true
	for k, v := range m {
		if !first {
			out += ","
		}
		first = false
		out += fmt.Sprintf("%q:%q", k, fmt.Sprint(v))
	}
	out += "}"
	return out
}

// UpdateClusterScore writes the final risk_score computed by the scorer.
func (s *Store) UpdateClusterScore(ctx context.Context, tx pgx.Tx, clusterID string, score int) error {
	_, err := tx.Exec(ctx, `UPDATE risk.clusters SET risk_score = $1 WHERE id = $2`, score, clusterID)
	return err
}

// LoadTouchedClusters fetches full cluster rows for the set of ids touched
// in this run. Needed by the scorer and the relations classifier.
func (s *Store) LoadTouchedClusters(ctx context.Context, tx pgx.Tx, clusterIDs []string) (map[string]*Cluster, error) {
	out := map[string]*Cluster{}
	if len(clusterIDs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, project_id, fingerprint, fingerprint_version, fingerprint_kind,
		       title, vuln_class, COALESCE(cwe_id, 0), COALESCE(owasp_category, ''),
		       COALESCE(language, ''),
		       COALESCE(canonical_route, ''), COALESCE(canonical_param, ''),
		       COALESCE(http_method, ''),
		       COALESCE(file_path, ''), COALESCE(enclosing_method, ''),
		       COALESCE(location_group, ''),
		       severity, risk_score, exposure, status, missing_run_count,
		       finding_count, surface_count,
		       first_seen_at, last_seen_at
		FROM risk.clusters
		WHERE id = ANY($1)
	`, clusterIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		c := &Cluster{}
		if err := rows.Scan(
			&c.ID, &c.ProjectID, &c.Fingerprint, &c.FingerprintVersion, &c.FingerprintKind,
			&c.Title, &c.VulnClass, &c.CWEID, &c.OWASPCategory,
			&c.Language,
			&c.CanonicalRoute, &c.CanonicalParam,
			&c.HTTPMethod,
			&c.FilePath, &c.EnclosingMethod,
			&c.LocationGroup,
			&c.Severity, &c.RiskScore, &c.Exposure, &c.Status, &c.MissingRunCount,
			&c.FindingCount, &c.SurfaceCount,
			&c.FirstSeenAt, &c.LastSeenAt,
		); err != nil {
			return nil, err
		}
		out[c.ID] = c
	}
	return out, rows.Err()
}

// DeleteStaleRelations removes relations touching the given cluster with
// a last_linked_run_id different from the current run.
func (s *Store) DeleteStaleRelations(ctx context.Context, tx pgx.Tx, clusterID, runID string) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM risk.cluster_relations
		WHERE (source_cluster_id = $1 OR target_cluster_id = $1)
		  AND last_linked_run_id <> $2
	`, clusterID, runID)
	return err
}

// UpsertRelation inserts or updates a cluster_relations row. Pair MUST be
// canonicalized by the caller via CanonicalizePair.
func (s *Store) UpsertRelation(ctx context.Context, tx pgx.Tx, r *Relation) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO risk.cluster_relations
			(project_id, source_cluster_id, target_cluster_id,
			 relation_type, confidence, rationale, last_linked_run_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (source_cluster_id, target_cluster_id, relation_type) DO UPDATE SET
			confidence = EXCLUDED.confidence,
			rationale = EXCLUDED.rationale,
			last_linked_run_id = EXCLUDED.last_linked_run_id
	`, r.ProjectID, r.SourceClusterID, r.TargetClusterID,
		r.RelationType, r.Confidence, r.Rationale, r.LastLinkedRunID)
	return err
}

// LoadRelationCandidatesByCWE returns other clusters in the same project
// with the same CWE. Used by rebuildRelations to find runtime_confirmation
// and same_cwe pairs.
func (s *Store) LoadRelationCandidatesByCWE(ctx context.Context, tx pgx.Tx, projectID string, cweID int, excludeClusterID string) ([]*Cluster, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, fingerprint_kind, COALESCE(cwe_id, 0), COALESCE(owasp_category, ''), vuln_class
		FROM risk.clusters
		WHERE project_id = $1
		  AND cwe_id = $2
		  AND id <> $3
		  AND status IN ('active', 'user_resolved', 'muted')
	`, projectID, cweID, excludeClusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cluster
	for rows.Next() {
		c := &Cluster{}
		if err := rows.Scan(&c.ID, &c.FingerprintKind, &c.CWEID, &c.OWASPCategory, &c.VulnClass); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HasActiveRuntimeConfirmation returns true if any runtime_confirmation
// relation with confidence >= BoostThreshold touches the cluster.
func (s *Store) HasActiveRuntimeConfirmation(ctx context.Context, tx pgx.Tx, clusterID string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM risk.cluster_relations
			WHERE (source_cluster_id = $1 OR target_cluster_id = $1)
			  AND relation_type = 'runtime_confirmation'
			  AND confidence >= $2
		)
	`, clusterID, BoostThreshold).Scan(&exists)
	return exists, err
}

// FirstPublicSurfaceForCluster returns the URL of any linked public
// surface entry for a DAST cluster, or empty string if none.
func (s *Store) FirstPublicSurfaceForCluster(ctx context.Context, tx pgx.Tx, clusterID string) (string, error) {
	var url string
	err := tx.QueryRow(ctx, `
		SELECT s.url
		FROM risk.clusters c
		JOIN scans.surface_entries s
		  ON s.project_id = c.project_id
		 AND lower(regexp_replace(s.url, '^https?://[^/]+', '')) = c.canonical_route
		WHERE c.id = $1
		  AND s.exposure = 'public'
		LIMIT 1
	`, clusterID).Scan(&url)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return url, nil
}

// FindingCountsByRouteAndParam reports whether >1 cluster_findings share
// the cluster's canonical route or param. Used by the scorer for
// SAME_ROUTE / SAME_PARAM boosts.
//
// In the MVP, we treat "multiple findings in the cluster" as both
// same_route and same_param for DAST clusters — the cluster itself
// is already defined by (route, param), so >1 members implies both.
func (s *Store) FindingCountsByRouteAndParam(ctx context.Context, tx pgx.Tx, clusterID string) (sameRoute, sameParam bool, err error) {
	var count int
	err = tx.QueryRow(ctx,
		`SELECT count(*) FROM risk.cluster_findings WHERE cluster_id = $1`, clusterID).Scan(&count)
	if err != nil {
		return false, false, err
	}
	return count > 1, count > 1, nil
}

// MarkMissingClustersAndResolve bumps missing_run_count for active
// clusters not touched in the current run and auto-resolves any that
// have exceeded the grace period. Returns the count of newly-resolved
// clusters.
func (s *Store) MarkMissingClustersAndResolve(ctx context.Context, tx pgx.Tx, projectID, runID string) (int, error) {
	if _, err := tx.Exec(ctx, `
		UPDATE risk.clusters
		SET missing_run_count = missing_run_count + 1
		WHERE project_id = $1
		  AND status = 'active'
		  AND (last_run_id IS NULL OR last_run_id <> $2)
	`, projectID, runID); err != nil {
		return 0, err
	}
	var resolved int
	err := tx.QueryRow(ctx, `
		WITH updated AS (
			UPDATE risk.clusters
			SET status = 'auto_resolved',
			    resolved_at = now(),
			    resolution_reason = 'no findings in ' || missing_run_count || ' consecutive runs'
			WHERE project_id = $1
			  AND status = 'active'
			  AND missing_run_count >= 3
			RETURNING id
		)
		SELECT count(*) FROM updated
	`, projectID).Scan(&resolved)
	return resolved, err
}
