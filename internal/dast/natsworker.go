package dast

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/crypto"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// NATSDispatch is the wire contract the orchestrator publishes on
// scan.dast.dispatch. Worker resolves everything else (target, auth, allowed
// hosts) from the database — keeping dispatch thin avoids stale or duplicated
// state between orchestrator and worker.
type NATSDispatch struct {
	ScanJobID string `json:"scan_job_id"`
	ProjectID string `json:"project_id"`
	ScanType  string `json:"scan_type"`
}

// NATSWorker wraps the DAST Worker with NATS JetStream message consumption
// and Postgres-backed scan resolution + persistence.
type NATSWorker struct {
	worker     *Worker
	pool       *pgxpool.Pool
	js         jetstream.JetStream
	signingKey []byte
	cipher     *crypto.AESGCM // optional — nil disables auth profile decrypt
	logger     zerolog.Logger
}

// NewNATSWorker creates a NATS-connected, DB-backed DAST worker. The cipher
// is used to decrypt auth_configs.encrypted_secret rows; pass nil when the
// AUTH_PROFILE_ENCRYPTION_KEY env var is unset (auth profiles will be skipped
// with an explicit failure on attached jobs).
func NewNATSWorker(
	js jetstream.JetStream,
	pool *pgxpool.Pool,
	worker *Worker,
	signingKey []byte,
	cipher *crypto.AESGCM,
	logger zerolog.Logger,
) *NATSWorker {
	return &NATSWorker{
		worker:     worker,
		pool:       pool,
		js:         js,
		signingKey: signingKey,
		cipher:     cipher,
		logger:     logger.With().Str("component", "dast-nats-worker").Logger(),
	}
}

// Start begins consuming DAST scan jobs from NATS JetStream. Blocks until ctx
// is cancelled.
func (nw *NATSWorker) Start(ctx context.Context) error {
	cons, err := nw.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "dast-worker",
		FilterSubject: "scan.dast.dispatch",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	nw.logger.Info().Msg("DAST worker waiting for scan jobs...")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}

		for msg := range msgs.Messages() {
			var dispatch NATSDispatch
			if err := json.Unmarshal(msg.Data(), &dispatch); err != nil {
				nw.logger.Error().Err(err).Msg("invalid DAST scan dispatch")
				msg.Ack()
				continue
			}

			nw.logger.Info().
				Str("scan_job_id", dispatch.ScanJobID).
				Str("project_id", dispatch.ProjectID).
				Msg("processing DAST scan")
			nw.processScan(ctx, dispatch)
			msg.Ack()
		}
	}
}

// processScan resolves the scan job from the DB, runs discovery + probes,
// and persists findings + status. Failure modes (missing target, no
// allowed_hosts, decrypt error) all surface as scan_jobs.status='failed'
// with a human-readable error_message so the user sees what went wrong.
func (nw *NATSWorker) processScan(ctx context.Context, dispatch NATSDispatch) {
	log := nw.logger.With().Str("scan_job_id", dispatch.ScanJobID).Logger()

	nw.markRunning(ctx, dispatch.ScanJobID, "discovering")
	nw.publishStatus(ctx, dispatch.ScanJobID, "running", "")

	scanJob, err := nw.loadScanJob(ctx, dispatch.ScanJobID)
	if err != nil {
		nw.failScan(ctx, dispatch.ScanJobID, "load scan_job: "+err.Error())
		log.Error().Err(err).Msg("scan_job load failed")
		return
	}

	if scanJob.TargetID == "" {
		nw.failScan(ctx, dispatch.ScanJobID, "DAST scan has no scan_target_id — attach a target before scheduling")
		return
	}

	target, err := nw.loadTarget(ctx, scanJob.TargetID)
	if err != nil {
		nw.failScan(ctx, dispatch.ScanJobID, "load target: "+err.Error())
		return
	}
	if target.BaseURL == "" {
		nw.failScan(ctx, dispatch.ScanJobID, "target has no base_url")
		return
	}

	authCfg, err := nw.resolveAuth(ctx, target.AuthConfigID, scanJob.ProjectID)
	if err != nil {
		nw.failScan(ctx, dispatch.ScanJobID, "auth profile: "+err.Error())
		return
	}

	allowedHosts := target.AllowedHosts()
	endpoints, err := DiscoverEndpoints(ctx, target.BaseURL, allowedHosts, DiscoveryConfig{})
	if err != nil {
		log.Warn().Err(err).Msg("endpoint discovery failed — proceeding with empty surface")
		endpoints = nil
	}
	log.Info().Int("endpoints", len(endpoints)).Msg("discovery complete")

	if err := nw.saveSurfaceEntries(ctx, scanJob.ProjectID, dispatch.ScanJobID, endpoints); err != nil {
		log.Warn().Err(err).Msg("surface_entries upsert failed (non-fatal)")
	}

	nw.markProgress(ctx, dispatch.ScanJobID, "scanning", 30)

	scanJobReq := ScanJob{
		ID:            dispatch.ScanJobID,
		TargetBaseURL: target.BaseURL,
		AllowedHosts:  allowedHosts,
		Endpoints:     endpoints,
		AuthConfig:    authCfg,
		ScopeConfig: scope.Config{
			AllowedHosts:  allowedHosts,
			PinnedIPs:     map[string][]net.IP{},
			MaxViolations: 5,
		},
		Concurrency:  10,
		RequestDelay: 0,
		Profile:      scanJob.ScanProfile,
	}

	result, err := nw.worker.ExecuteScan(ctx, scanJobReq)
	if err != nil {
		nw.failScan(ctx, dispatch.ScanJobID, err.Error())
		return
	}

	nw.markProgress(ctx, dispatch.ScanJobID, "persisting", 85)
	for _, f := range result.Findings {
		nw.upsertFinding(ctx, scanJob.ProjectID, dispatch.ScanJobID, f)
		nw.publishFinding(ctx, scanJob.ProjectID, dispatch.ScanJobID, f)
	}

	if result.Status == "completed" {
		nw.markCompleted(ctx, dispatch.ScanJobID, len(result.Findings))
	} else {
		nw.failScan(ctx, dispatch.ScanJobID, result.Error)
	}
	nw.publishStatus(ctx, dispatch.ScanJobID, result.Status, result.Error)

	log.Info().
		Str("status", result.Status).
		Int("findings", len(result.Findings)).
		Int("endpoints", len(endpoints)).
		Int("requests", result.TotalRequests).
		Msg("DAST scan finished")
}

// scanJobRow holds the columns we need from scans.scan_jobs.
type scanJobRow struct {
	ID          string
	ProjectID   string
	ScanType    string
	ScanProfile string
	TargetID    string
}

func (nw *NATSWorker) loadScanJob(ctx context.Context, id string) (*scanJobRow, error) {
	row := nw.pool.QueryRow(ctx, `
		SELECT id::text, project_id::text, scan_type, COALESCE(scan_profile, ''),
		       COALESCE(scan_target_id::text, '')
		  FROM scans.scan_jobs WHERE id = $1`, id)
	var s scanJobRow
	if err := row.Scan(&s.ID, &s.ProjectID, &s.ScanType, &s.ScanProfile, &s.TargetID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("scan_job %s not found", id)
		}
		return nil, err
	}
	return &s, nil
}

// targetRow holds the columns we need from core.scan_targets.
type targetRow struct {
	ID             string
	BaseURL        string
	AllowedDomains []string
	MaxRPS         int
	AuthConfigID   string
}

// AllowedHosts returns the set of hosts in scope. Falls back to the base URL
// host when allowed_domains is empty so a target with no explicit allowlist
// still produces a valid scan scope.
func (t targetRow) AllowedHosts() []string {
	if len(t.AllowedDomains) > 0 {
		return t.AllowedDomains
	}
	if t.BaseURL == "" {
		return nil
	}
	host := t.BaseURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	return []string{host}
}

func (nw *NATSWorker) loadTarget(ctx context.Context, id string) (*targetRow, error) {
	row := nw.pool.QueryRow(ctx, `
		SELECT id::text, base_url, COALESCE(allowed_domains, '{}'),
		       COALESCE(max_rps, 10), COALESCE(auth_config_id::text, '')
		  FROM core.scan_targets WHERE id = $1`, id)
	var t targetRow
	if err := row.Scan(&t.ID, &t.BaseURL, &t.AllowedDomains, &t.MaxRPS, &t.AuthConfigID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("target %s not found", id)
		}
		return nil, err
	}
	return &t, nil
}

func (nw *NATSWorker) resolveAuth(ctx context.Context, authConfigID, projectID string) (*authbroker.AuthConfig, error) {
	if authConfigID == "" {
		return nil, nil
	}
	if nw.cipher == nil {
		return nil, errors.New("AUTH_PROFILE_ENCRYPTION_KEY not configured but target has auth profile attached")
	}
	row := nw.pool.QueryRow(ctx, `
		SELECT auth_type, encrypted_secret, COALESCE(config, '{}'::jsonb)
		  FROM auth.auth_configs WHERE id = $1`, authConfigID)
	var (
		authType   string
		ciphertext []byte
		configJSON []byte
	)
	if err := row.Scan(&authType, &ciphertext, &configJSON); err != nil {
		return nil, fmt.Errorf("auth_config %s: %w", authConfigID, err)
	}
	return ResolveAuthConfig(nw.cipher, projectID, authType, ciphertext, configJSON)
}

// markRunning sets scan_jobs.status='running' and started_at if not yet set.
func (nw *NATSWorker) markRunning(ctx context.Context, id, phase string) {
	progress, _ := json.Marshal(map[string]any{"phase": phase, "percent": 5})
	_, err := nw.pool.Exec(ctx, `
		UPDATE scans.scan_jobs
		   SET status = 'running',
		       started_at = COALESCE(started_at, now()),
		       progress = $2::jsonb,
		       updated_at = now()
		 WHERE id = $1`, id, progress)
	if err != nil {
		nw.logger.Warn().Err(err).Msg("markRunning failed")
	}
}

func (nw *NATSWorker) markProgress(ctx context.Context, id, phase string, percent int) {
	progress, _ := json.Marshal(map[string]any{"phase": phase, "percent": percent})
	_, err := nw.pool.Exec(ctx, `
		UPDATE scans.scan_jobs
		   SET progress = $2::jsonb, updated_at = now()
		 WHERE id = $1`, id, progress)
	if err != nil {
		nw.logger.Warn().Err(err).Msg("markProgress failed")
	}
}

func (nw *NATSWorker) markCompleted(ctx context.Context, id string, findingCount int) {
	progress, _ := json.Marshal(map[string]any{"phase": "completed", "percent": 100, "findings": findingCount})
	_, err := nw.pool.Exec(ctx, `
		UPDATE scans.scan_jobs
		   SET status = 'completed',
		       completed_at = now(),
		       progress = $2::jsonb,
		       updated_at = now()
		 WHERE id = $1`, id, progress)
	if err != nil {
		nw.logger.Warn().Err(err).Msg("markCompleted failed")
	}
}

func (nw *NATSWorker) failScan(ctx context.Context, id, errMsg string) {
	if errMsg == "" {
		errMsg = "scan failed"
	}
	progress, _ := json.Marshal(map[string]any{"phase": "failed", "percent": 0})
	_, err := nw.pool.Exec(ctx, `
		UPDATE scans.scan_jobs
		   SET status = 'failed',
		       error_message = $2,
		       completed_at = COALESCE(completed_at, now()),
		       progress = $3::jsonb,
		       updated_at = now()
		 WHERE id = $1`, id, errMsg, progress)
	if err != nil {
		nw.logger.Warn().Err(err).Msg("failScan failed")
	}
}

// saveSurfaceEntries upserts one row per discovered endpoint so the UI can
// show the attack surface that was actually exercised.
func (nw *NATSWorker) saveSurfaceEntries(ctx context.Context, projectID, scanJobID string, endpoints []Endpoint) error {
	for _, ep := range endpoints {
		surfaceID := surfaceFingerprint(scanJobID, ep)
		urlStr := ep.absoluteURL()
		_, err := nw.pool.Exec(ctx, `
			INSERT INTO scans.surface_entries
			   (id, project_id, scan_job_id, surface_type, url, method, exposure, title, metadata, first_seen_at, last_seen_at, scan_count, observation_count)
			 VALUES ($1, $2, $3, 'api_endpoint', $4, $5, 'unknown', $6, '{}'::jsonb, now(), now(), 1, 1)
			 ON CONFLICT (id) DO UPDATE
			    SET last_seen_at = now(),
			        scan_count = scans.surface_entries.scan_count + 1,
			        observation_count = scans.surface_entries.observation_count + 1`,
			surfaceID, projectID, scanJobID, urlStr, ep.Method, ep.Path,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func surfaceFingerprint(scanJobID string, ep Endpoint) string {
	h := sha256.Sum256([]byte(scanJobID + "|" + ep.Method + "|" + ep.Path))
	return hex.EncodeToString(h[:16])
}

// upsertFinding writes a finding row, deduplicating by fingerprint so re-scans
// don't pile up duplicates. New rows get last_seen_at = first_seen_at;
// existing rows just bump last_seen_at + scan_count.
//
// Enrichment: the rule's metadata (CWE, OWASP category, CVSS score+vector,
// risk score, tags, remediation guidance) is looked up and persisted. The
// description is rendered with What/Impact/Remediation/References sections
// so the UI can present an actionable finding instead of a one-liner.
//
// Evidence (the captured request/response pair) is serialized to JSON,
// hashed, and written into evidence_ref/_hash/_size so the UI can render
// the exact HTTP exchange that proved the finding.
func (nw *NATSWorker) upsertFinding(ctx context.Context, projectID, scanJobID string, f Finding) {
	fingerprint := dastFingerprint(f)
	findingID := uuid.New().String()

	var existingID string
	err := nw.pool.QueryRow(ctx,
		`SELECT id::text FROM findings.findings WHERE fingerprint = $1`, fingerprint,
	).Scan(&existingID)
	if err == nil {
		_, _ = nw.pool.Exec(ctx, `
			UPDATE findings.findings
			   SET last_seen_at = now(),
			       scan_count = scan_count + 1,
			       scan_job_id = $2,
			       updated_at = now()
			 WHERE id = $1`, existingID, scanJobID)
		return
	}

	meta := LookupRuleMetadata(f.RuleID)
	desc := meta.RenderDescription(f.MatchDetail)
	if desc == "" {
		// Truly unmapped rule with no match detail — fall back to title so the
		// NOT NULL description column doesn't refuse the insert.
		desc = f.Title
	}

	evidenceJSON, evidenceHash, evidenceSize := serializeEvidence(f.Evidence)

	// Optional columns get nil-or-value via helpers so the SQL stays one shape.
	_, err = nw.pool.Exec(ctx, `
		INSERT INTO findings.findings
		   (id, project_id, scan_job_id, finding_type, fingerprint,
		    title, description,
		    severity, confidence, status,
		    url, http_method, parameter, rule_id,
		    cwe_id, owasp_category, cvss_score, cvss_vector, risk_score,
		    tags,
		    evidence_ref, evidence_hash, evidence_size,
		    first_seen_at, last_seen_at, scan_count)
		 VALUES ($1, $2, $3, 'dast', $4,
		         $5, $6,
		         $7, $8, 'new',
		         $9, $10, $11, $12,
		         $13, $14, $15, $16, $17,
		         $18,
		         $19, $20, $21,
		         now(), now(), 1)`,
		findingID, projectID, scanJobID, fingerprint,
		f.Title, desc,
		strings.ToLower(f.Severity), strings.ToLower(f.Confidence),
		f.URL, f.Method, f.Parameter, f.RuleID,
		nullIntZero(meta.CWEID), nullStringEmpty(meta.OWASPCategory),
		nullFloatZero(meta.CVSSScore), nullStringEmpty(meta.CVSSVector), nullFloatZero(meta.RiskScore),
		meta.Tags,
		nullStringEmpty(evidenceJSON), nullStringEmpty(evidenceHash), nullInt64Zero(evidenceSize),
	)
	if err != nil {
		nw.logger.Error().Err(err).Str("rule_id", f.RuleID).Msg("dast finding insert failed")
	}
}

// serializeEvidence produces the (json, sha256, size) tuple that goes into
// findings.findings.evidence_*. Returns ("", "", 0) when no evidence was
// captured (e.g. the matcher fired without an HTTP exchange).
func serializeEvidence(ev *Evidence) (string, string, int64) {
	if ev == nil {
		return "", "", 0
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return "", "", 0
	}
	return string(b), ev.SHA256, int64(len(b))
}

// nullIntZero, nullInt64Zero, nullFloatZero, nullStringEmpty turn a
// zero-valued primitive into a SQL NULL so optional columns stay NULL
// instead of being bound as "0" / "" — which would fail CHECK constraints
// and pollute filters.
func nullIntZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func nullInt64Zero(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

func nullFloatZero(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}

func nullStringEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func dastFingerprint(f Finding) string {
	h := sha256.Sum256([]byte(f.RuleID + "|" + f.Method + "|" + f.URL + "|" + f.Parameter))
	return hex.EncodeToString(h[:])
}

// publishFinding broadcasts to the correlation engine via signed NATS message.
// Mirrors the SAST worker's scan.results.sast envelope shape.
func (nw *NATSWorker) publishFinding(ctx context.Context, projectID, scanJobID string, f Finding) {
	findingData := map[string]any{
		"scan_job_id":  scanJobID,
		"project_id":   projectID,
		"finding_type": "dast",
		"rule_id":      f.RuleID,
		"title":        f.Title,
		"category":     f.Category,
		"severity":     f.Severity,
		"confidence":   f.Confidence,
		"url":          f.URL,
		"method":       f.Method,
		"match_detail": f.MatchDetail,
	}
	if f.Evidence != nil {
		findingData["evidence_sha256"] = f.Evidence.SHA256
	}

	data, _ := json.Marshal(findingData)
	sig := sc_nats.SignMessage(nw.signingKey, data)
	msg := &natsgo.Msg{
		Subject: "scan.results.dast",
		Data:    data,
		Header:  natsgo.Header{"X-Signature": []string{sig}},
	}
	if _, err := nw.js.PublishMsg(ctx, msg); err != nil {
		nw.logger.Warn().Err(err).Msg("publishFinding failed")
	}
}

func (nw *NATSWorker) publishStatus(ctx context.Context, scanID, status, errorMsg string) {
	data, _ := json.Marshal(map[string]string{
		"scan_job_id": scanID,
		"status":      status,
		"error":       errorMsg,
		"worker_type": "dast",
	})
	sig := sc_nats.SignMessage(nw.signingKey, data)
	msg := &natsgo.Msg{
		Subject: "scan.status.update",
		Data:    data,
		Header:  natsgo.Header{"X-Signature": []string{sig}},
	}
	if _, err := nw.js.PublishMsg(ctx, msg); err != nil {
		nw.logger.Warn().Err(err).Msg("publishStatus failed")
	}
}
