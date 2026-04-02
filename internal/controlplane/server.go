package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/controlplane/api"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
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
	cfg      ServerConfig
	logger   zerolog.Logger
	pool     *pgxpool.Pool
	jwtMgr   *auth.JWTManager
	sessions *auth.SessionStore
	emitter  *audit.Emitter
	limiter  *ratelimit.Limiter
	js       jetstream.JetStream
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
) *Server {
	return &Server{
		cfg:      cfg,
		logger:   logger,
		pool:     pool,
		jwtMgr:   jwtMgr,
		sessions: sessions,
		emitter:  emitter,
		limiter:  limiter,
		js:       js,
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
	"/healthz":            true,
	"/api/v1/auth/login":  true,
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
	handlers := api.NewHandlers(s.pool, s.jwtMgr, s.sessions, s.emitter, s.js, s.logger)

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

	// Scan targets
	mux.HandleFunc("POST /api/v1/projects/{id}/scan-targets", handlers.CreateScanTarget)
	mux.HandleFunc("GET /api/v1/projects/{id}/scan-targets", handlers.ListScanTargets)

	// Scans
	mux.HandleFunc("POST /api/v1/projects/{id}/scans", handlers.CreateScan)
	mux.HandleFunc("GET /api/v1/scans/{id}", handlers.GetScan)
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", handlers.CancelScan)

	// Findings
	mux.HandleFunc("GET /api/v1/findings", handlers.ListFindings)
	mux.HandleFunc("PATCH /api/v1/findings/{id}/status", handlers.UpdateFindingStatus)

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

	// Build middleware chain: outermost first
	var handler http.Handler = mux
	handler = conditionalAuthMiddleware(s.jwtMgr, s.sessions)(handler)
	if s.limiter != nil {
		handler = ratelimit.HTTPMiddleware(s.limiter, 100, time.Minute)(handler)
	}
	handler = loggingMiddleware(s.logger)(handler)
	handler = requestIDMiddleware(handler)

	// Start metrics server
	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", observability.MetricsHandler())
		metricsMux.HandleFunc("GET /healthz", observability.HealthHandler())
		addr := fmt.Sprintf(":%s", s.cfg.MetricsPort)
		s.logger.Info().Str("addr", addr).Msg("metrics server starting")
		if err := http.ListenAndServe(addr, metricsMux); err != nil {
			s.logger.Error().Err(err).Msg("metrics server failed")
		}
	}()

	addr := fmt.Sprintf(":%s", s.cfg.Port)
	s.logger.Info().Str("addr", addr).Msg("control plane starting")
	return http.ListenAndServe(addr, handler)
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
