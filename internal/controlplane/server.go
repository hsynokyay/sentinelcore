package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/replay"
	"github.com/sentinelcore/sentinelcore/internal/controlplane/api"
	"github.com/sentinelcore/sentinelcore/internal/dast/authz"
	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/internal/export/evidence"
	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/internal/risk"
	"github.com/sentinelcore/sentinelcore/pkg/apikeys"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	sc_cors "github.com/sentinelcore/sentinelcore/pkg/cors"
	"github.com/sentinelcore/sentinelcore/pkg/crypto/aesgcm"
	sc_csrf "github.com/sentinelcore/sentinelcore/pkg/csrf"
	"github.com/sentinelcore/sentinelcore/pkg/httpsec"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
	"github.com/sentinelcore/sentinelcore/pkg/ratelimit"
	"github.com/sentinelcore/sentinelcore/pkg/sso"
	"github.com/sentinelcore/sentinelcore/pkg/ssostate"
)

// ServerConfig holds configuration for the control plane server.
type ServerConfig struct {
	Port        string
	MetricsPort string
}

// Server is the control plane HTTP server.
type Server struct {
	cfg       ServerConfig
	logger    zerolog.Logger
	pool      *pgxpool.Pool
	jwtMgr    *auth.JWTManager
	sessions  *auth.SessionStore
	emitter   *audit.Emitter
	limiter   *ratelimit.Limiter
	js        jetstream.JetStream
	nc        *nats.Conn    // for health checks
	redis     *redis.Client // for health checks + SSO state store
	rbacCache *policy.Cache
	denier    auth.AuditDenier

	// DAST wiring (populated via Set*Store builders).
	bundleStore  bundles.BundleStore // nil until SetBundleStore is called
	roleStore    authz.RoleStore     // nil until SetRoleStore is called
	circuitStore replay.CircuitStore // nil until SetCircuitStore is called

	// Optional SSO wiring (populated by WithSSO).
	ssoEncKey     []byte
	publicBaseURL string
}

// SetBundleStore configures the DAST bundle store used by the bundles CRUD
// endpoints. Must be called before Start if bundle endpoints are needed;
// without it the endpoints return 503 Service Unavailable.
func (s *Server) SetBundleStore(store bundles.BundleStore) {
	s.bundleStore = store
}

// SetRoleStore configures the DAST role store used by the approval/reject/list
// endpoints for role-gated access control. Must be called before Start if DAST
// approval endpoints are needed; without it the role gate returns 403.
func (s *Server) SetRoleStore(store authz.RoleStore) {
	s.roleStore = store
}

// SetCircuitStore configures the replay circuit breaker store used by the
// circuit reset endpoint. Without it, the endpoint returns 503.
func (s *Server) SetCircuitStore(store replay.CircuitStore) {
	s.circuitStore = store
}

// WithSSO enables the OIDC SSO surface. Must be called before Start.
// If encKey is not exactly 32 bytes or redis is nil, SSO endpoints remain
// disabled and return 503 SSO_DISABLED. The redis client is reused from
// the one already passed to NewServer (no separate connection pool).
func (s *Server) WithSSO(_redisClient *redis.Client, encKey []byte, publicBaseURL string) *Server {
	s.ssoEncKey = encKey
	s.publicBaseURL = publicBaseURL
	return s
}

// NewServer creates a new control plane server.
func NewServer(
	cfg ServerConfig,
	logger zerolog.Logger,
	pool *pgxpool.Pool,
	jwtMgr *auth.JWTManager,
	sessions *auth.SessionStore,
	emitter *audit.Emitter,
	limiter *ratelimit.Limiter,
	js jetstream.JetStream,
	nc *nats.Conn,
	redisClient *redis.Client,
) *Server {
	// Wire API key auth metrics counter.
	auth.APIKeyAuthCounterFunc = func(status string) {
		observability.APIKeyAuths.WithLabelValues(status).Inc()
	}

	// Wire API key resolver so the auth middleware can authenticate
	// requests with "Bearer sc_..." tokens.
	auth.SetAPIKeyResolver(func(ctx context.Context, plainKey string) (*auth.APIKeyResolved, error) {
		rk, err := apikeys.Resolve(ctx, pool, plainKey)
		if err != nil || rk == nil {
			return nil, err
		}
		return &auth.APIKeyResolved{
			KeyID:  rk.KeyID,
			OrgID:  rk.OrgID,
			UserID: rk.UserID,
			Role:   rk.Role,
			Scopes: rk.Scopes,
		}, nil
	})

	// Phase 1: initialize the RBAC cache from the DB. If the auth.* tables
	// don't exist yet (pre-migration-024 state), Reload returns an error
	// and we start with an empty cache. With an empty cache, every
	// Principal.Can(perm) call returns false, so every RequirePermission
	// wrapper yields 403. During the planned deploy sequence the binary
	// goes out FIRST on a pre-migration DB; clients can still log in
	// (/auth/login doesn't require a permission), but protected routes
	// 403 until migration 024 runs and the 60s safety poll populates
	// the cache on next refresh.
	cache := policy.NewCache()
	if err := cache.Reload(context.Background(), pool); err != nil {
		logger.Warn().Err(err).Msg("rbac cache initial reload failed; starting empty (all RequirePermission checks will deny until migration 024 is applied)")
	}
	denier := audit.NewAuthzDenier(emitter)

	return &Server{
		cfg:       cfg,
		logger:    logger,
		pool:      pool,
		jwtMgr:    jwtMgr,
		sessions:  sessions,
		emitter:   emitter,
		limiter:   limiter,
		js:        js,
		nc:        nc,
		redis:     redisClient,
		rbacCache: cache,
		denier:    denier,
	}
}

// authz wraps an http.HandlerFunc with RequirePermission enforcement.
// The outer conditionalAuthMiddleware already populates the Principal
// in context — authz only adds the permission check. Used for every
// business route that needs a permission check; routes that should be
// accessible to any authenticated caller (e.g. /users/me, /auth/me)
// bypass this helper and register via mux.HandleFunc / mux.Handle directly.
func (s *Server) authz(perm string, next http.HandlerFunc) http.Handler {
	return auth.RequirePermission(perm, s.rbacCache, s.denier)(http.HandlerFunc(next))
}

// stepUp composes authz + RequireStepUp so destructive admin routes
// carry BOTH "has the capability" and "recently re-authed" gates.
// Phase 8 §4.1 A7. A missing session store is a programming error;
// we no-op (warn once) rather than crash on cold boot.
func (s *Server) stepUp(perm string, next http.HandlerFunc) http.Handler {
	inner := s.authz(perm, next)
	if s.sessions == nil {
		s.logger.Warn().Str("perm", perm).Msg("stepUp: session store nil, step-up gate disabled")
		return inner
	}
	cfg := httpsec.StepUpConfig{
		Sessions: s.sessions,
		GetJTI: func(ctx context.Context) (string, bool) {
			if p, ok := auth.PrincipalFromContext(ctx); ok && p.JTI != "" {
				return p.JTI, true
			}
			return "", false
		},
		MaxAge: 5 * time.Minute,
		ErrorWriter: func(w http.ResponseWriter, status int, msg, code string) {
			// Match the controlplane writeError envelope shape.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"` + msg + `","code":"` + code + `"}`))
		},
	}
	return httpsec.RequireStepUp(cfg)(inner)
}

// requestIDMiddleware generates a UUID request ID and injects it into context and response header.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := uuid.New().String()
		w.Header().Set("X-Request-ID", reqID)
		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type ctxKey string

const requestIDKey ctxKey = "request_id"

// loggingMiddleware logs method, path, status, and duration.
func loggingMiddleware(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			logger.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", sw.status).
				Dur("duration", time.Since(start)).
				Str("request_id", requestID(r.Context())).
				Msg("request")
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func requestID(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// RBACCache returns the server's RBAC cache so the startup code can
// attach a pg_notify listener to it.
func (s *Server) RBACCache() *policy.Cache {
	return s.rbacCache
}

// skipAuthPaths defines exact paths that do not require authentication.
var skipAuthPaths = map[string]bool{
	"/healthz":                 true,
	"/readyz":                  true,
	"/api/v1/auth/login":       true,
	"/api/v1/auth/refresh":     true,
	"/api/v1/system/health":    true,
	"/api/v1/auth/sso/enabled": true,
}

// skipAuthPrefixes matches prefixes that bypass auth. Used for the OIDC
// /start and /callback endpoints where the URL carries dynamic org +
// provider segments.
var skipAuthPrefixes = []string{
	"/api/v1/auth/sso/", // matches /auth/sso/{org}/{provider}/(start|callback)
}

// conditionalAuthMiddleware applies auth middleware except for skip paths.
func conditionalAuthMiddleware(jwtMgr *auth.JWTManager, sessions *auth.SessionStore) func(http.Handler) http.Handler {
	authMw := auth.AuthMiddleware(jwtMgr, sessions)
	return func(next http.Handler) http.Handler {
		authed := authMw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// /api/v1/auth/sso/logout is the ONE path under /auth/sso/
			// that DOES require auth — exclude it from the prefix bypass.
			if r.URL.Path == "/api/v1/auth/sso/logout" {
				authed.ServeHTTP(w, r)
				return
			}
			if skipAuthPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			for _, p := range skipAuthPrefixes {
				if len(r.URL.Path) >= len(p) && r.URL.Path[:len(p)] == p {
					next.ServeHTTP(w, r)
					return
				}
			}
			authed.ServeHTTP(w, r)
		})
	}
}

// Start starts the control plane HTTP server and the metrics server.
func (s *Server) Start(ctx context.Context) error {
	// Construct the risk worker so manual rebuilds via the HTTP API can
	// reuse the same correlator plumbing as the NATS-driven worker. Run()
	// is not started from here — the scan-worker process owns the
	// NATS-driven loop; this instance exists solely so RebuildProjectManually
	// can be invoked by the rebuild endpoint.
	riskWorker := risk.NewWorker(s.js, s.pool, s.logger)

	handlers := api.NewHandlers(s.pool, s.jwtMgr, s.sessions, s.emitter, s.js, s.logger, riskWorker, s.rbacCache)

	// Wire the evidence-pack BlobClient so DownloadExport can stream
	// archives from disk. EXPORT_BLOB_DIR matches the export-worker env.
	exportBlobDir := os.Getenv("EXPORT_BLOB_DIR")
	if exportBlobDir == "" {
		exportBlobDir = "/var/lib/sentinelcore/exports"
	}
	if blob, blobErr := evidence.NewFilesystemBlob(exportBlobDir); blobErr != nil {
		s.logger.Warn().Err(blobErr).Str("dir", exportBlobDir).Msg("evidence-pack blob store unavailable; downloads will return 503")
	} else {
		handlers.SetExportBlob(blob)
	}

	// Optional SSO wiring: skip cleanly if prerequisites absent so the
	// rest of the control plane still boots on clusters that haven't
	// rotated in an encryption key yet. Endpoints return SSO_DISABLED.
	if s.redis != nil && len(s.ssoEncKey) == 32 {
		enc, err := aesgcm.NewEncryptor(s.ssoEncKey)
		if err != nil {
			s.logger.Error().Err(err).Msg("sso encryptor init failed; sso disabled")
		} else {
			providers := sso.NewProviderStore(s.pool, enc)
			mappings := sso.NewMappingStore(s.pool)
			state := ssostate.New(s.redis)
			clients := sso.NewClientCache()
			events := sso.NewEventStore(s.pool)
			handlers.
				WithSSO(providers, mappings, state, clients, events).
				WithPublicBaseURL(s.publicBaseURL)
			s.logger.Info().Msg("sso enabled")
		}
	} else {
		s.logger.Info().Msg("sso disabled (no redis or encryption key)")
	}

	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /healthz", observability.HealthHandler())
	mux.HandleFunc("GET /api/v1/system/health", handlers.SystemHealth)
	mux.HandleFunc("GET /api/v1/system/version", handlers.SystemVersion)

	// Auth
	mux.HandleFunc("POST /api/v1/auth/login", handlers.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", handlers.Refresh)
	mux.HandleFunc("POST /api/v1/auth/logout", handlers.Logout)
	meHandler := &api.MeHandler{Cache: s.rbacCache}
	mux.Handle("GET /api/v1/auth/me", auth.AuthMiddleware(s.jwtMgr, s.sessions)(meHandler))

	// Organizations
	mux.Handle("POST /api/v1/organizations", s.authz("organizations.manage", handlers.CreateOrganization))
	mux.Handle("GET /api/v1/organizations", s.authz("organizations.read", handlers.ListOrganizations))
	mux.Handle("GET /api/v1/organizations/{id}", s.authz("organizations.read", handlers.GetOrganization))
	mux.Handle("PATCH /api/v1/organizations/{id}", s.authz("organizations.manage", handlers.UpdateOrganization))

	// Teams
	mux.Handle("POST /api/v1/organizations/{org_id}/teams", s.authz("teams.manage", handlers.CreateTeam))
	mux.Handle("GET /api/v1/organizations/{org_id}/teams", s.authz("teams.read", handlers.ListTeams))
	mux.Handle("POST /api/v1/teams/{id}/members", s.authz("teams.manage", handlers.AddTeamMember))
	mux.Handle("GET /api/v1/teams/{id}/members", s.authz("teams.read", handlers.ListTeamMembers))

	// Users
	mux.Handle("POST /api/v1/users", s.authz("users.manage", handlers.CreateUser))
	mux.Handle("GET /api/v1/users", s.authz("users.read", handlers.ListUsers))
	mux.HandleFunc("GET /api/v1/users/me", handlers.GetCurrentUser)

	// Projects
	mux.Handle("POST /api/v1/projects", s.authz("projects.manage", handlers.CreateProject))
	mux.Handle("GET /api/v1/projects", s.authz("projects.read", handlers.ListProjects))
	mux.Handle("GET /api/v1/projects/{id}", s.authz("projects.read", handlers.GetProject))
	mux.Handle("PATCH /api/v1/projects/{id}", s.authz("projects.manage", handlers.UpdateProject))

	// Source artifacts (SAST intake)
	mux.HandleFunc("POST /api/v1/projects/{id}/artifacts", handlers.CreateSourceArtifact)
	mux.HandleFunc("GET /api/v1/projects/{id}/artifacts", handlers.ListSourceArtifacts)
	mux.HandleFunc("GET /api/v1/artifacts/{id}", handlers.GetSourceArtifact)
	mux.HandleFunc("DELETE /api/v1/artifacts/{id}", handlers.DeleteSourceArtifact)

	// Auth profiles (DAST credentials)
	mux.HandleFunc("POST /api/v1/projects/{id}/auth-profiles", handlers.CreateAuthProfile)
	mux.HandleFunc("GET /api/v1/projects/{id}/auth-profiles", handlers.ListAuthProfiles)
	mux.HandleFunc("GET /api/v1/auth-profiles/{id}", handlers.GetAuthProfile)
	mux.HandleFunc("PATCH /api/v1/auth-profiles/{id}", handlers.UpdateAuthProfile)
	mux.HandleFunc("DELETE /api/v1/auth-profiles/{id}", handlers.DeleteAuthProfile)

	// API keys. Revoke + rotate are destructive — step-up-gated.
	mux.Handle("POST /api/v1/api-keys", s.authz("api_keys.manage", handlers.CreateAPIKey))
	mux.HandleFunc("GET /api/v1/api-keys", handlers.ListAPIKeys)
	mux.Handle("DELETE /api/v1/api-keys/{id}", s.stepUp("api_keys.manage", handlers.RevokeAPIKey))
	mux.Handle("POST /api/v1/api-keys/{id}/rotate", s.stepUp("api_keys.manage", handlers.RotateAPIKey))

	// Scan targets
	mux.Handle("POST /api/v1/projects/{id}/scan-targets", s.authz("targets.manage", handlers.CreateScanTarget))
	mux.Handle("GET /api/v1/projects/{id}/scan-targets", s.authz("targets.read", handlers.ListScanTargets))
	mux.HandleFunc("GET /api/v1/scan-targets/{id}", handlers.GetScanTarget)
	mux.HandleFunc("PATCH /api/v1/scan-targets/{id}", handlers.UpdateScanTarget)
	mux.HandleFunc("DELETE /api/v1/scan-targets/{id}", handlers.DeleteScanTarget)

	// Scans
	mux.Handle("POST /api/v1/projects/{id}/scans", s.authz("scans.run", handlers.CreateScan))
	mux.Handle("GET /api/v1/scans/{id}", s.authz("scans.read", handlers.GetScan))
	mux.Handle("POST /api/v1/scans/{id}/cancel", s.authz("scans.cancel", handlers.CancelScan))

	// Findings
	mux.Handle("GET /api/v1/findings", s.authz("findings.read", handlers.ListFindings))
	mux.HandleFunc("GET /api/v1/findings/{id}", handlers.GetFinding)
	mux.Handle("PATCH /api/v1/findings/{id}/status", s.authz("findings.triage", handlers.UpdateFindingStatus))
	mux.HandleFunc("GET /api/v1/findings/{id}/export.md", handlers.ExportFindingMarkdown)
	mux.HandleFunc("GET /api/v1/findings/{id}/export.sarif", handlers.ExportFindingSARIF)

	// Risk correlation
	mux.HandleFunc("GET /api/v1/risks", handlers.ListRisks)
	mux.HandleFunc("GET /api/v1/risks/{id}", handlers.GetRisk)
	mux.HandleFunc("GET /api/v1/risks/{id}/history", handlers.RiskHistory)
	mux.HandleFunc("POST /api/v1/risks/{id}/resolve", handlers.ResolveRisk)
	mux.HandleFunc("POST /api/v1/risks/{id}/reopen", handlers.ReopenRisk)
	mux.HandleFunc("POST /api/v1/risks/{id}/mute", handlers.MuteRisk)
	mux.HandleFunc("POST /api/v1/projects/{id}/risks/rebuild", handlers.RebuildRisks)

	// Scans (list)
	mux.HandleFunc("GET /api/v1/scans", handlers.ListScans)
	mux.HandleFunc("GET /api/v1/scans/{id}/report.md", handlers.ExportScanMarkdown)
	mux.HandleFunc("GET /api/v1/scans/{id}/report.sarif", handlers.ExportScanSARIF)

	// Governance
	mux.HandleFunc("GET /api/v1/governance/settings", handlers.GetGovernanceSettings)
	mux.HandleFunc("PUT /api/v1/governance/settings", handlers.UpdateGovernanceSettings)
	mux.HandleFunc("GET /api/v1/governance/approvals", handlers.ListApprovals)
	mux.HandleFunc("GET /api/v1/governance/approvals/{id}", handlers.GetApproval)
	mux.HandleFunc("POST /api/v1/governance/approvals/{id}/decide", handlers.DecideApproval)
	// Phase 5 governance-ops: two-person approvals.
	mux.HandleFunc("POST /api/v1/governance/approvals", handlers.CreateApprovalRequestHandler)
	mux.HandleFunc("POST /api/v1/governance/approvals/{id}/decisions", handlers.SubmitApprovalDecision)
	// Phase 9 §4.1 multi-approver vote endpoints. Go through the FSM
	// so requester-cannot-vote, duplicate-vote, terminal-state refusal
	// are all enforced server-side regardless of UI behaviour.
	mux.HandleFunc("POST /api/v1/governance/approvals/{id}/approve", handlers.ApproveRequest)
	mux.HandleFunc("POST /api/v1/governance/approvals/{id}/reject", handlers.RejectRequest)
	mux.HandleFunc("POST /api/v1/governance/emergency-stop", handlers.ActivateEmergencyStop)
	mux.HandleFunc("POST /api/v1/governance/emergency-stop/lift", handlers.LiftEmergencyStop)
	mux.HandleFunc("GET /api/v1/governance/emergency-stop/active", handlers.ListActiveEmergencyStops)
	// Phase 5 governance-ops: SLA dashboard + per-project policies.
	mux.HandleFunc("GET /api/v1/governance/sla/dashboard", handlers.SLADashboard)
	mux.HandleFunc("GET /api/v1/governance/sla/violations", handlers.ListSLAViolationsHandler)
	mux.HandleFunc("GET /api/v1/governance/sla/policies/{project_id}", handlers.GetProjectSLAPolicyHandler)
	mux.HandleFunc("PUT /api/v1/governance/sla/policies/{project_id}", handlers.PutProjectSLAPolicyHandler)
	mux.HandleFunc("DELETE /api/v1/governance/sla/policies/{project_id}", handlers.DeleteProjectSLAPolicyHandler)

	// Phase 5 governance-ops: compliance catalogs + mappings.
	mux.HandleFunc("GET /api/v1/compliance/catalogs", handlers.ListComplianceCatalogs)
	mux.HandleFunc("POST /api/v1/compliance/catalogs", handlers.CreateComplianceCatalog)
	mux.HandleFunc("GET /api/v1/compliance/catalogs/{catalog_id}/items", handlers.ListComplianceCatalogItems)
	mux.HandleFunc("POST /api/v1/compliance/catalogs/{catalog_id}/items", handlers.CreateComplianceItem)
	mux.HandleFunc("GET /api/v1/compliance/mappings", handlers.ListComplianceMappings)
	mux.HandleFunc("POST /api/v1/compliance/mappings", handlers.CreateComplianceMapping)
	mux.HandleFunc("DELETE /api/v1/compliance/mappings/{id}", handlers.DeleteComplianceMapping)
	mux.HandleFunc("GET /api/v1/compliance/resolve", handlers.ResolveComplianceControls)

	// Phase 5 governance-ops: evidence pack export jobs.
	mux.HandleFunc("POST /api/v1/governance/exports", handlers.CreateExport)
	mux.HandleFunc("GET /api/v1/governance/exports", handlers.ListExports)
	mux.HandleFunc("GET /api/v1/governance/exports/{id}", handlers.GetExport)
	mux.HandleFunc("GET /api/v1/governance/exports/{id}/download", handlers.DownloadExport)

	// Finding extensions
	mux.HandleFunc("POST /api/v1/findings/{id}/assign", handlers.AssignFinding)
	mux.HandleFunc("POST /api/v1/findings/{id}/legal-hold", handlers.SetLegalHold)

	// Notifications
	mux.HandleFunc("GET /api/v1/notifications", handlers.ListNotificationsHandler)
	mux.HandleFunc("POST /api/v1/notifications/{id}/read", handlers.MarkNotificationRead)
	mux.HandleFunc("POST /api/v1/notifications/read-all", handlers.MarkAllNotificationsRead)
	mux.HandleFunc("GET /api/v1/notifications/unread-count", handlers.GetUnreadCount)

	// Webhooks
	mux.HandleFunc("GET /api/v1/webhooks", handlers.ListWebhooks)
	mux.HandleFunc("POST /api/v1/webhooks", handlers.CreateWebhook)
	mux.HandleFunc("PUT /api/v1/webhooks/{id}", handlers.UpdateWebhook)
	mux.HandleFunc("DELETE /api/v1/webhooks/{id}", handlers.DeleteWebhook)
	mux.HandleFunc("POST /api/v1/webhooks/{id}/test", handlers.TestWebhook)

	// Retention
	mux.HandleFunc("GET /api/v1/retention/policies", handlers.GetRetentionPolicies)
	mux.HandleFunc("PUT /api/v1/retention/policies", handlers.UpdateRetentionPolicies)
	mux.HandleFunc("GET /api/v1/retention/records", handlers.ListRetentionRecords)
	mux.HandleFunc("GET /api/v1/retention/stats", handlers.GetRetentionStats)

	// Reports
	mux.HandleFunc("GET /api/v1/reports/findings-summary", handlers.FindingsSummary)
	mux.HandleFunc("GET /api/v1/reports/triage-metrics", handlers.TriageMetrics)
	mux.HandleFunc("GET /api/v1/reports/compliance-status", handlers.ComplianceStatus)
	mux.HandleFunc("GET /api/v1/reports/scan-activity", handlers.ScanActivity)

	// Surface inventory
	mux.HandleFunc("GET /api/v1/surface", handlers.ListSurfaceEntries)
	mux.HandleFunc("GET /api/v1/surface/stats", handlers.GetSurfaceStats)

	// Ops / observability
	mux.HandleFunc("GET /api/v1/ops/queue", handlers.GetQueueStatus)
	mux.HandleFunc("GET /api/v1/ops/webhooks", handlers.GetWebhookStatus)

	// Audit log
	mux.HandleFunc("GET /api/v1/audit", handlers.ListAuditEvents)
	mux.Handle("GET /api/v1/audit/exports", s.authz("audit.export", handlers.ListAuditExports))
	mux.Handle("POST /api/v1/audit/exports", s.authz("audit.export", handlers.CreateAuditExport))
	mux.Handle("GET /api/v1/audit/integrity", s.authz("audit.verify", handlers.AuditIntegrity))

	// SSO — public (no auth). Anti-enumeration (unknown org → empty list)
	// enforced in the handler itself.
	mux.HandleFunc("GET /api/v1/auth/sso/{org}/{provider}/start", handlers.StartSSO)
	mux.HandleFunc("GET /api/v1/auth/sso/{org}/{provider}/callback", handlers.SSOCallback)
	mux.HandleFunc("GET /api/v1/auth/sso/enabled", handlers.EnabledSSOProviders)

	// SSO logout — authenticated via outer conditionalAuthMiddleware
	// (exempted from the /auth/sso/ public-prefix bypass).
	mux.HandleFunc("POST /api/v1/auth/sso/logout", handlers.SSOLogout)

	// SSO admin (sso.manage).
	mux.Handle("GET /api/v1/sso/providers", s.authz("sso.manage", handlers.ListSSOProviders))
	mux.Handle("POST /api/v1/sso/providers", s.authz("sso.manage", handlers.CreateSSOProvider))
	mux.Handle("GET /api/v1/sso/providers/{id}", s.authz("sso.manage", handlers.GetSSOProvider))
	mux.Handle("PATCH /api/v1/sso/providers/{id}", s.authz("sso.manage", handlers.UpdateSSOProvider))
	mux.Handle("DELETE /api/v1/sso/providers/{id}", s.stepUp("sso.manage", handlers.DeleteSSOProvider))

	mux.Handle("GET /api/v1/sso/providers/{id}/mappings", s.authz("sso.manage", handlers.ListSSOMappings))
	mux.Handle("POST /api/v1/sso/providers/{id}/mappings", s.authz("sso.manage", handlers.CreateSSOMapping))
	mux.Handle("DELETE /api/v1/sso/providers/{id}/mappings/{mapping_id}", s.authz("sso.manage", handlers.DeleteSSOMapping))

	mux.Handle("GET /api/v1/sso/providers/{id}/history", s.authz("sso.manage", handlers.SSOLoginHistory))

	// DAST auth bundles. The store is set via SetBundleStore; if nil the handler
	// returns 503 so the rest of the server stays functional during incremental
	// rollout. Auth is enforced by the global conditionalAuthMiddleware above.
	bundlesHandler := NewBundlesHandler(s.bundleStore)
	mux.HandleFunc("POST /api/v1/dast/bundles", func(w http.ResponseWriter, r *http.Request) {
		if s.bundleStore == nil {
			http.Error(w, "bundle store not configured", http.StatusServiceUnavailable)
			return
		}
		bundlesHandler.Create(w, r)
	})
	mux.HandleFunc("POST /api/v1/dast/bundles/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		if s.bundleStore == nil {
			http.Error(w, "bundle store not configured", http.StatusServiceUnavailable)
			return
		}
		bundlesHandler.Revoke(w, r)
	})

	// Approval routes — role-gated. Auth (JWT/session) is provided by the
	// global conditionalAuthMiddleware; DAST role check is layered on top.
	// If roleStore is nil the middleware returns 503 to avoid a nil-pointer
	// panic while still providing a clear operational signal.
	effectiveRoleStore := s.roleStore
	if effectiveRoleStore == nil {
		effectiveRoleStore = unavailableRoleStore{}
	}
	mux.Handle("POST /api/v1/dast/bundles/{id}/approve",
		authz.RequireDASTRole(effectiveRoleStore, authz.RoleReviewer)(http.HandlerFunc(bundlesHandler.Approve)))
	mux.Handle("POST /api/v1/dast/bundles/{id}/reject",
		authz.RequireDASTRole(effectiveRoleStore, authz.RoleReviewer)(http.HandlerFunc(bundlesHandler.Reject)))
	mux.Handle("GET /api/v1/dast/bundles",
		authz.RequireAnyDASTRole(effectiveRoleStore, authz.RoleReviewer, authz.RoleRecordingAdmin)(http.HandlerFunc(bundlesHandler.ListPending)))

	// Circuit reset — recording_admin only. The handler returns 503 if the
	// circuit store has not been wired via SetCircuitStore.
	mux.Handle("POST /api/v1/dast/bundles/{id}/circuit/reset",
		authz.RequireDASTRole(effectiveRoleStore, authz.RoleRecordingAdmin)(CircuitResetHandler(s.circuitStore)))

	// Bundle re-record — recording_admin only. Supersedes the source bundle
	// and returns a fresh pending_review draft id for the operator to record
	// against. Wired via the BundleStore (PostgresStore satisfies the
	// narrower bundles.ReRecordStore interface that ReRecord requires).
	var reRecordStore bundles.ReRecordStore
	if rrs, ok := s.bundleStore.(bundles.ReRecordStore); ok {
		reRecordStore = rrs
	}
	mux.Handle("POST /api/v1/dast/bundles/{id}/re-record",
		authz.RequireDASTRole(effectiveRoleStore, authz.RoleRecordingAdmin)(ReRecordHandler(reRecordStore)))

	// Build middleware chain: outermost first
	var handler http.Handler = mux

	// CSRF: validates CSRF token on state-changing cookie-authenticated requests.
	// Placed between auth and routes so cookies are available.
	corsOriginForCSRF := os.Getenv("CORS_ORIGIN")
	if corsOriginForCSRF == "" {
		corsOriginForCSRF = "http://localhost:3000"
	}
	handler = sc_csrf.Middleware(sc_csrf.Config{
		AllowedOrigins: strings.Split(corsOriginForCSRF, ","),
	}, s.logger)(handler)

	handler = conditionalAuthMiddleware(s.jwtMgr, s.sessions)(handler)
	if s.limiter != nil {
		handler = ratelimit.HTTPMiddleware(s.limiter, ratelimit.DefaultTierConfig(), s.logger)(handler)
	}
	handler = loggingMiddleware(s.logger)(handler)
	handler = requestIDMiddleware(handler)

	// CORS: must be outermost application-layer middleware so
	// preflight is handled before auth.
	corsOrigin := os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		corsOrigin = "http://localhost:3000"
	}
	handler = sc_cors.Middleware(sc_cors.Config{
		AllowedOrigins: strings.Split(corsOrigin, ","),
	})(handler)

	// httpsec: outermost security layer — request-size cap + HSTS +
	// nosniff + frame-deny + referrer + permissions-policy. Sits
	// OUTSIDE CORS so security headers land on every response,
	// including preflight; sits INSIDE nothing so the body cap
	// triggers before the handler reads anything.
	handler = httpsec.Chain(handler,
		append(httpsec.Defaults(),
			httpsec.WithUploadException(
				10<<20, // 10 MiB
				"/api/v1/source-artifacts/",
				"/api/v1/projects/", // includes source artifact upload sub-paths
			),
		)...,
	)

	// Register readiness endpoint (checks DB, Redis, NATS).
	mux.HandleFunc("GET /readyz", observability.ReadinessHandler(observability.ReadinessDeps{
		DB:    s.pool,
		Redis: s.redis,
		NATS:  s.nc,
	}))

	// Start metrics server
	metricsAddr := fmt.Sprintf(":%s", s.cfg.MetricsPort)
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", observability.MetricsHandler())
	metricsMux.HandleFunc("GET /healthz", observability.HealthHandler())
	metricsServer := &http.Server{Addr: metricsAddr, Handler: metricsMux}
	go func() {
		s.logger.Info().Str("addr", metricsAddr).Msg("metrics server starting")
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msg("metrics server failed")
		}
	}()

	// Start main API server
	addr := fmt.Sprintf(":%s", s.cfg.Port)
	apiServer := &http.Server{Addr: addr, Handler: handler}

	// Graceful shutdown: wait for context cancellation, then drain connections.
	go func() {
		<-ctx.Done()
		s.logger.Info().Msg("shutdown signal received, draining connections...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error().Err(err).Msg("API server shutdown error")
		}
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error().Err(err).Msg("metrics server shutdown error")
		}
		s.logger.Info().Msg("servers shut down gracefully")
	}()

	s.logger.Info().Str("addr", addr).Msg("control plane starting")
	if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// WriteError writes a JSON error response.
func WriteError(w http.ResponseWriter, status int, message, code string) {
	WriteJSON(w, status, map[string]string{"error": message, "code": code})
}

// unavailableRoleStore is a sentinel RoleStore used when the real store has not
// been configured. Every method returns an error so the role-gate middleware
// responds 500 instead of panicking on a nil interface.
type unavailableRoleStore struct{}

func (unavailableRoleStore) Grant(_ context.Context, _, _ string, _ authz.Role) error {
	return fmt.Errorf("role store not configured")
}
func (unavailableRoleStore) Revoke(_ context.Context, _ string, _ authz.Role) error {
	return fmt.Errorf("role store not configured")
}
func (unavailableRoleStore) HasRole(_ context.Context, _ string, _ authz.Role) (bool, error) {
	return false, fmt.Errorf("role store not configured")
}
func (unavailableRoleStore) ListUserRoles(_ context.Context, _ string) ([]authz.Role, error) {
	return nil, fmt.Errorf("role store not configured")
}
func (unavailableRoleStore) ListUsersWithRole(_ context.Context, _ authz.Role) ([]string, error) {
	return nil, fmt.Errorf("role store not configured")
}
