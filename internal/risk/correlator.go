package risk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

// Correlator is the main rebuild engine. It is stateless except for its
// dependencies — a Store and a logger — and is safe to reuse across runs.
type Correlator struct {
	store  *Store
	logger zerolog.Logger
}

func NewCorrelator(store *Store, logger zerolog.Logger) *Correlator {
	return &Correlator{store: store, logger: logger.With().Str("component", "risk-correlator").Logger()}
}

// RebuildProject is the single entry point for a correlation run. It
// opens a transaction, acquires the project lock, processes every
// active finding, and commits atomically. Any error aborts and rolls
// back the entire run.
func (c *Correlator) RebuildProject(ctx context.Context, projectID, trigger string, triggeredByScan *string) error {
	start := time.Now()
	tx, err := c.store.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := c.store.AcquireProjectLock(ctx, tx, projectID); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}

	runID, err := c.store.CreateRun(ctx, tx, projectID, trigger, triggeredByScan)
	if err != nil {
		return fmt.Errorf("create run: %w", err)
	}

	findings, err := c.store.LoadActiveFindings(ctx, tx, projectID)
	if err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("load findings: %w", err)
	}

	touched := make(map[string]struct{})
	created := 0

	for _, f := range findings {
		fp, kind, version := ComputeFingerprint(f)
		if fp == "" {
			continue // unsupported finding type
		}
		cl := buildClusterFromFinding(f, fp, kind, version)
		clusterID, wasInserted, err := c.store.UpsertCluster(ctx, tx, runID, cl)
		if err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("upsert cluster: %w", err)
		}
		if wasInserted {
			created++
		}
		touched[clusterID] = struct{}{}

		if err := c.store.UpsertClusterFinding(ctx, tx, clusterID, f.ID, f.Type, runID); err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("upsert cluster_finding: %w", err)
		}
	}

	// Project-scoped stale cleanup (catches finding migrations).
	if err := c.store.DeleteStaleClusterFindings(ctx, tx, projectID, runID); err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("delete stale cluster_findings: %w", err)
	}

	touchedIDs := keysOf(touched)

	if err := c.store.RecomputeClusterAggregates(ctx, tx, touchedIDs); err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("recompute aggregates: %w", err)
	}

	// Evidence rebuild: delete prior, then re-emit from fresh relations + scorer.
	if err := c.store.DeleteStaleEvidence(ctx, tx, touchedIDs, runID); err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("delete stale evidence: %w", err)
	}

	clusters, err := c.store.LoadTouchedClusters(ctx, tx, touchedIDs)
	if err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("load touched clusters: %w", err)
	}

	for clusterID := range touched {
		cluster := clusters[clusterID]
		if cluster == nil {
			continue
		}
		if err := c.rebuildRelations(ctx, tx, projectID, cluster, runID); err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("rebuild relations: %w", err)
		}
		if err := c.rescoreCluster(ctx, tx, cluster, runID); err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("rescore cluster: %w", err)
		}
	}

	resolved, err := c.store.MarkMissingClustersAndResolve(ctx, tx, projectID, runID)
	if err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("mark missing: %w", err)
	}

	if err := c.store.FinishRun(ctx, tx, runID, Run{
		ClustersTouched:   len(touched),
		ClustersCreated:   created,
		ClustersResolved:  resolved,
		FindingsProcessed: len(findings),
	}); err != nil {
		return fmt.Errorf("finish run: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	c.logger.Info().
		Str("project_id", projectID).
		Str("run_id", runID).
		Int("touched", len(touched)).
		Int("created", created).
		Int("resolved", resolved).
		Int("findings", len(findings)).
		Dur("duration", time.Since(start)).
		Msg("risk correlation run completed")

	return nil
}

// rebuildRelations finds candidate clusters with the same CWE and emits
// relation rows. Stale relations are deleted first so a single rebuild
// produces an exact snapshot.
func (c *Correlator) rebuildRelations(ctx context.Context, tx pgx.Tx, projectID string, cluster *Cluster, runID string) error {
	if err := c.store.DeleteStaleRelations(ctx, tx, cluster.ID, runID); err != nil {
		return err
	}
	if cluster.CWEID == 0 {
		return nil
	}
	candidates, err := c.store.LoadRelationCandidatesByCWE(ctx, tx, projectID, cluster.CWEID, cluster.ID)
	if err != nil {
		return err
	}
	for _, cand := range candidates {
		relType, conf, rationale := ClassifyRelation(cluster, cand, false)
		if relType == "" {
			continue
		}
		src, tgt := CanonicalizePair(cluster.ID, cand.ID)
		r := &Relation{
			ProjectID:       projectID,
			SourceClusterID: src,
			TargetClusterID: tgt,
			RelationType:    relType,
			Confidence:      conf,
			Rationale:       rationale,
			LastLinkedRunID: runID,
		}
		if err := c.store.UpsertRelation(ctx, tx, r); err != nil {
			return err
		}
	}
	return nil
}

// rescoreCluster consults the store for all scoring inputs, runs the pure
// ComputeScore function, and persists the result + evidence rows.
func (c *Correlator) rescoreCluster(ctx context.Context, tx pgx.Tx, cluster *Cluster, runID string) error {
	runtime, err := c.store.HasActiveRuntimeConfirmation(ctx, tx, cluster.ID)
	if err != nil {
		return err
	}

	var publicURL string
	if cluster.FingerprintKind == "dast_route" {
		publicURL, err = c.store.FirstPublicSurfaceForCluster(ctx, tx, cluster.ID)
		if err != nil {
			return err
		}
	}

	sameRoute, sameParam := false, false
	if cluster.FingerprintKind == "dast_route" && cluster.FindingCount > 1 {
		sameRoute = cluster.CanonicalRoute != ""
		sameParam = cluster.CanonicalParam != ""
	}

	result := ComputeScore(ScoreInputs{
		Severity:         cluster.Severity,
		FingerprintKind:  cluster.FingerprintKind,
		RuntimeConfirmed: runtime,
		PublicExposure:   publicURL != "",
		PublicSurfaceURL: publicURL,
		SameRoute:        sameRoute,
		SameParam:        sameParam,
		CanonicalRoute:   cluster.CanonicalRoute,
		CanonicalParam:   cluster.CanonicalParam,
	})

	for i := range result.Evidence {
		e := &result.Evidence[i]
		e.ClusterID = cluster.ID
		e.SourceRunID = runID
		if err := c.store.InsertEvidence(ctx, tx, e); err != nil {
			return err
		}
	}

	return c.store.UpdateClusterScore(ctx, tx, cluster.ID, result.Total)
}

// buildClusterFromFinding derives the cluster-level fields from a source
// finding. For DAST clusters the canonical route/param come from the
// finding's normalized URL; for SAST clusters the file path and location
// group carry the identity.
func buildClusterFromFinding(f *Finding, fp, kind string, version int16) *Cluster {
	cl := &Cluster{
		ProjectID:          f.ProjectID,
		Fingerprint:        fp,
		FingerprintVersion: version,
		FingerprintKind:    kind,
		VulnClass:          vulnClassFromCWE(f.CWEID),
		CWEID:              f.CWEID,
		OWASPCategory:      f.OWASPCategory,
		Severity:           f.Severity,
	}
	switch kind {
	case "dast_route":
		cl.CanonicalRoute = NormalizeRoute(f.URL)
		cl.CanonicalParam = NormalizeParam(f.Parameter)
		cl.HTTPMethod = strings.ToUpper(f.HTTPMethod)
		cl.Title = fmt.Sprintf("%s on %s %s", titleCase(cl.VulnClass), cl.HTTPMethod, cl.CanonicalRoute)
	case "sast_file":
		cl.Language = strings.ToLower(f.Language)
		cl.FilePath = NormalizeFilePath(f.FilePath)
		cl.EnclosingMethod = f.FunctionName
		cl.LocationGroup = LocationGroup(f.FunctionName, f.LineStart, f.CWEID)
		where := cl.FilePath
		if cl.EnclosingMethod != "" {
			where = cl.EnclosingMethod + " in " + cl.FilePath
		}
		cl.Title = fmt.Sprintf("%s in %s", titleCase(cl.VulnClass), where)
	}
	return cl
}

// vulnClassFromCWE maps a CWE id to a short vuln_class string. The mapping
// is deliberately coarse for MVP; any unmapped CWE returns "other".
func vulnClassFromCWE(cweID int) string {
	switch cweID {
	case 89:
		return "sql_injection"
	case 78:
		return "command_injection"
	case 22:
		return "path_traversal"
	case 79:
		return "xss"
	case 502:
		return "unsafe_deserialization"
	case 918:
		return "ssrf"
	case 798, 259:
		return "hardcoded_secret"
	case 327, 328:
		return "weak_crypto"
	case 601:
		return "open_redirect"
	case 611:
		return "xxe"
	case 532:
		return "sensitive_logging"
	}
	return "other"
}

func titleCase(class string) string {
	if class == "" {
		return "Risk"
	}
	parts := strings.Split(class, "_")
	for i, p := range parts {
		if len(p) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
