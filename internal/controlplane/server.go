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
	"github.com/sentinelcore/sentinelcore/internal/risk"
	"github.com/sentinelcore/sentinelcore/pkg/apikeys"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	sc_cors "github.com/sentinelcore/sentinelcore/pkg/cors"
	sc_csrf "github.com/sentinelcore/sentinelcore/pkg/csrf"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
	"github.com/sentinelcore/sentinelcore/pkg/ratelimit"
)

// ServerConfig holds configuration for the control plane server.
type ServerConfig struct {
	Port        string
	MetricsPort string
}

// Server is the control plane HTTP server.
type Server struct {
	cfg         ServerConfig
	logger      zerolog.Logger
	pool        *pgxpool.Pool
	jwtMgr      *auth.JWTManager
	sessions    *auth.SessionStore
	emitter     *audit.Emitter
	limiter     *ratelimit.Limiter
	js          jetstream.JetStream
	nc          *nats.Conn         // for health checks
	redis       *redis.Client      // for health checks
	bundleStore  bundles.BundleStore  // nil until SetBundleStore is called
	roleStore    authz.RoleStore      // nil until SetRoleStore is called
	circuitStore replay.CircuitStore  // nil until SetCircuitStore is called
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

	return &Server{
		cfg:      cfg,
		logger:   logger,
		pool:     pool,
		jwtMgr:   jwtMgr,
		sessions: sessions,
		emitter:  emitter,
		limiter:  limiter,
		js:       js,
		nc:       nc,
		redis:    redisClient,
	}
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

// skipAuthPaths defines paths that do not require authentication.
var skipAuthPaths = map[string]bool{
	"/healthz":              true,
	"/readyz":               true,
	"/api/v1/auth/login":    true,
	"/api/v1/system/health": true,
}

// conditionalAuthMiddleware applies auth middleware except for skip paths.
func conditionalAuthMiddleware(jwtMgr *auth.JWTManager, sessions *auth.SessionStore) func(http.Handler) http.Handler {
	authMw := auth.AuthMiddleware(jwtMgr, sessions)
	return func(next http.Handler) http.Handler {
		authed := authMw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skipAuthPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
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

	handlers := api.NewHandlers(s.pool, s.jwtMgr, s.sessions, s.emitter, s.js, s.logger, riskWorker)

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

	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /healthz", observability.HealthHandler())
	mux.HandleFunc("GET /api/v1/system/health", handlers.SystemHealth)
	mux.HandleFunc("GET /api/v1/system/version", handlers.SystemVersion)

	// Auth
	mux.HandleFunc("POST /api/v1/auth/login", handlers.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", handlers.Refresh)
	mux.HandleFunc("POST /api/v1/auth/logout", handlers.Logout)

	// Organizations
	mux.HandleFunc("POST /api/v1/organizations", handlers.CreateOrganization)
	mux.HandleFunc("GET /api/v1/organizations", handlers.ListOrganizations)
	mux.HandleFunc("GET /api/v1/organizations/{id}", handlers.GetOrganization)
	mux.HandleFunc("PATCH /api/v1/organizations/{id}", handlers.UpdateOrganization)

	// Teams
	mux.HandleFunc("POST /api/v1/organizations/{org_id}/teams", handlers.CreateTeam)
	mux.HandleFunc("GET /api/v1/organizations/{org_id}/teams", handlers.ListTeams)
	mux.HandleFunc("POST /api/v1/teams/{id}/members", handlers.AddTeamMember)
	mux.HandleFunc("GET /api/v1/teams/{id}/members", handlers.ListTeamMembers)

	// Users
	mux.HandleFunc("POST /api/v1/users", handlers.CreateUser)
	mux.HandleFunc("GET /api/v1/users", handlers.ListUsers)
	mux.HandleFunc("GET /api/v1/users/me", handlers.GetCurrentUser)

	// Projects
	mux.HandleFunc("POST /api/v1/projects", handlers.CreateProject)
	mux.HandleFunc("GET /api/v1/projects", handlers.ListProjects)
	mux.HandleFunc("GET /api/v1/projects/{id}", handlers.GetProject)
	mux.HandleFunc("PATCH /api/v1/projects/{id}", handlers.UpdateProject)

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

	// API keys
	mux.HandleFunc("POST /api/v1/api-keys", handlers.CreateAPIKey)
	mux.HandleFunc("GET /api/v1/api-keys", handlers.ListAPIKeys)
	mux.HandleFunc("DELETE /api/v1/api-keys/{id}", handlers.RevokeAPIKey)

	// Scan targets
	mux.HandleFunc("POST /api/v1/projects/{id}/scan-targets", handlers.CreateScanTarget)
	mux.HandleFunc("GET /api/v1/projects/{id}/scan-targets", handlers.ListScanTargets)
	mux.HandleFunc("GET /api/v1/scan-targets/{id}", handlers.GetScanTarget)
	mux.HandleFunc("PATCH /api/v1/scan-targets/{id}", handlers.UpdateScanTarget)
	mux.HandleFunc("DELETE /api/v1/scan-targets/{id}", handlers.DeleteScanTarget)

	// Scans
	mux.HandleFunc("POST /api/v1/projects/{id}/scans", handlers.CreateScan)
	mux.HandleFunc("GET /api/v1/scans/{id}", handlers.GetScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", handlers.CancelScan)

	// Findings
	mux.HandleFunc("GET /api/v1/findings", handlers.ListFindings)
	mux.HandleFunc("GET /api/v1/findings/{id}", handlers.GetFinding)
	mux.HandleFunc("PATCH /api/v1/findings/{id}/status", handlers.UpdateFindingStatus)
	mux.HandleFunc("GET /api/v1/findings/{id}/export.md", handlers.ExportFindingMarkdown)
	mux.HandleFunc("GET /api/v1/findings/{id}/export.sarif", handlers.ExportFindingSARIF)

	// Risk correlation
	mux.HandleFunc("GET /api/v1/risks", handlers.ListRisks)
	mux.HandleFunc("GET /api/v1/risks/{id}", handlers.GetRisk)
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

	// CORS: must be outermost to handle preflight before auth
	corsOrigin := os.Getenv("CORS_ORIGIN")
	if corsOrigin == "" {
		corsOrigin = "http://localhost:3000"
	}
	handler = sc_cors.Middleware(sc_cors.Config{
		AllowedOrigins: strings.Split(corsOrigin, ","),
	})(handler)

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
