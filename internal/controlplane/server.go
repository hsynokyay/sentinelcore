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

	"github.com/sentinelcore/sentinelcore/internal/controlplane/api"
	"github.com/sentinelcore/sentinelcore/internal/policy"
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
	cfg       ServerConfig
	logger    zerolog.Logger
	pool      *pgxpool.Pool
	jwtMgr    *auth.JWTManager
	sessions  *auth.SessionStore
	emitter   *audit.Emitter
	limiter   *ratelimit.Limiter
	js        jetstream.JetStream
	nc        *nats.Conn    // for health checks
	redis     *redis.Client // for health checks
	rbacCache *policy.Cache
	denier    auth.AuditDenier
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

// RBACCache returns the server's RBAC cache so the startup code can
// attach a pg_notify listener to it.
func (s *Server) RBACCache() *policy.Cache {
	return s.rbacCache
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

	handlers := api.NewHandlers(s.pool, s.jwtMgr, s.sessions, s.emitter, s.js, s.logger, riskWorker, s.rbacCache)

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
	mux.Handle("POST /api/v1/api-keys", s.authz("api_keys.manage", handlers.CreateAPIKey))
	mux.HandleFunc("GET /api/v1/api-keys", handlers.ListAPIKeys)
	mux.HandleFunc("DELETE /api/v1/api-keys/{id}", handlers.RevokeAPIKey)
	mux.Handle("POST /api/v1/api-keys/{id}/rotate", s.authz("api_keys.manage", handlers.RotateAPIKey))

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
	mux.HandleFunc("POST /api/v1/governance/emergency-stop", handlers.ActivateEmergencyStop)
	mux.HandleFunc("POST /api/v1/governance/emergency-stop/lift", handlers.LiftEmergencyStop)
	mux.HandleFunc("GET /api/v1/governance/emergency-stop/active", handlers.ListActiveEmergencyStops)

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
