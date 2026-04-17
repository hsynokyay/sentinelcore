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
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/controlplane/api"
	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/crypto/aesgcm"
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
	rbacCache *policy.Cache
	denier    auth.AuditDenier

	// Optional SSO wiring (populated by WithSSO).
	redis         *redis.Client
	ssoEncKey     []byte
	publicBaseURL string
}

// WithSSO enables the OIDC SSO surface. Must be called before Start.
// If encKey is not exactly 32 bytes or redisClient is nil, SSO endpoints
// remain disabled and return 503 SSO_DISABLED.
func (s *Server) WithSSO(redisClient *redis.Client, encKey []byte, publicBaseURL string) *Server {
	s.redis = redisClient
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
) *Server {
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
	"/healthz":              true,
	"/api/v1/auth/login":    true,
	"/api/v1/auth/refresh":  true,
	"/api/v1/system/health": true,
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
	handlers := api.NewHandlers(s.pool, s.jwtMgr, s.sessions, s.emitter, s.js, s.logger, s.rbacCache)

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
			handlers.
				WithSSO(providers, mappings, state, clients).
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

	// Scan targets
	mux.Handle("POST /api/v1/projects/{id}/scan-targets", s.authz("targets.manage", handlers.CreateScanTarget))
	mux.Handle("GET /api/v1/projects/{id}/scan-targets", s.authz("targets.read", handlers.ListScanTargets))

	// Scans
	mux.Handle("POST /api/v1/projects/{id}/scans", s.authz("scans.run", handlers.CreateScan))
	mux.Handle("GET /api/v1/scans/{id}", s.authz("scans.read", handlers.GetScan))
	mux.Handle("POST /api/v1/scans/{id}/cancel", s.authz("scans.cancel", handlers.CancelScan))

	// Findings
	mux.Handle("GET /api/v1/findings", s.authz("findings.read", handlers.ListFindings))
	mux.Handle("PATCH /api/v1/findings/{id}/status", s.authz("findings.triage", handlers.UpdateFindingStatus))

	// API keys
	mux.Handle("POST /api/v1/api-keys", s.authz("api_keys.manage", handlers.CreateAPIKey))
	mux.Handle("POST /api/v1/api-keys/{id}/rotate", s.authz("api_keys.manage", handlers.RotateAPIKey))

	// SSO — public (no auth). Rate limiting handled by the outer HTTP
	// limiter middleware; the anti-enumeration property of
	// EnabledSSOProviders (unknown orgs → empty list) is enforced in the
	// handler itself.
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
	mux.Handle("DELETE /api/v1/sso/providers/{id}", s.authz("sso.manage", handlers.DeleteSSOProvider))

	mux.Handle("GET /api/v1/sso/providers/{id}/mappings", s.authz("sso.manage", handlers.ListSSOMappings))
	mux.Handle("POST /api/v1/sso/providers/{id}/mappings", s.authz("sso.manage", handlers.CreateSSOMapping))
	mux.Handle("DELETE /api/v1/sso/providers/{id}/mappings/{mapping_id}", s.authz("sso.manage", handlers.DeleteSSOMapping))

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
