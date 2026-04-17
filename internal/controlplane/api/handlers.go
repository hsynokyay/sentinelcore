package api

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/sso"
	"github.com/sentinelcore/sentinelcore/pkg/ssostate"
)

// Handlers contains all API handler methods.
type Handlers struct {
	pool         *pgxpool.Pool
	jwtMgr       *auth.JWTManager
	sessions     *auth.SessionStore
	emitter      *audit.Emitter
	js           jetstream.JetStream
	logger       zerolog.Logger
	rbacCache    *policy.Cache
	audit        *audit.Emitter // alias for emitter; used by CreateAPIKey
	ssoProviders  *sso.ProviderStore
	ssoMappings   *sso.MappingStore
	ssoState      *ssostate.Store
	ssoClients    *sso.ClientCache
	publicBaseURL string // e.g. "https://sentinelcore.example.com" — no trailing slash
}

// WithSSO wires the SSO stores onto an existing Handlers.
// Called from server bootstrap after all stores are constructed.
// Passing nil arguments is allowed and disables the SSO surface until
// it is populated (useful for tests that don't exercise SSO).
func (h *Handlers) WithSSO(providers *sso.ProviderStore, mappings *sso.MappingStore, state *ssostate.Store, clients *sso.ClientCache) *Handlers {
	h.ssoProviders = providers
	h.ssoMappings = mappings
	h.ssoState = state
	h.ssoClients = clients
	return h
}

// WithPublicBaseURL sets the external base URL (no trailing slash) used
// to construct SSO redirect URIs. If empty, the callback derives a URL
// from the incoming request which works for single-origin deploys but
// breaks when the IdP has a pinned redirect_uri.
func (h *Handlers) WithPublicBaseURL(url string) *Handlers {
	h.publicBaseURL = url
	return h
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	pool *pgxpool.Pool,
	jwtMgr *auth.JWTManager,
	sessions *auth.SessionStore,
	emitter *audit.Emitter,
	js jetstream.JetStream,
	logger zerolog.Logger,
	rbacCache *policy.Cache,
) *Handlers {
	return &Handlers{
		pool:      pool,
		jwtMgr:    jwtMgr,
		sessions:  sessions,
		emitter:   emitter,
		js:        js,
		logger:    logger,
		rbacCache: rbacCache,
		audit:     emitter,
	}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message, code string) {
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}

// decodeJSON decodes a JSON request body into v.
func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// requireAuth extracts the authenticated user from context, returning error if not found.
func requireAuth(w http.ResponseWriter, r *http.Request) *auth.UserContext {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "authentication required", "UNAUTHORIZED")
		return nil
	}
	return user
}
