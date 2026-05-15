package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/export/evidence"
	"github.com/sentinelcore/sentinelcore/internal/policy"
	"github.com/sentinelcore/sentinelcore/internal/remediation"
	"github.com/sentinelcore/sentinelcore/internal/risk"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/sso"
	"github.com/sentinelcore/sentinelcore/pkg/ssostate"
)

// errNotVisible is a sentinel error returned by RLS-scoped lookups when the
// requested row either does not exist or is not visible to the caller's org.
var errNotVisible = errors.New("resource not visible")

// userError carries a user-facing validation message out of a transaction
// closure so the HTTP handler can surface it with the correct status code.
type userError struct {
	code int
	msg  string
}

func (e userError) Error() string { return e.msg }

// Handlers contains all API handler methods.
type Handlers struct {
	pool        *pgxpool.Pool
	jwtMgr      *auth.JWTManager
	sessions    *auth.SessionStore
	emitter     *audit.Emitter
	js          jetstream.JetStream
	logger      zerolog.Logger
	remediation *remediation.Registry
	riskWorker  *risk.Worker
	rbacCache   *policy.Cache
	audit       *audit.Emitter // alias for emitter; used by CreateAPIKey

	// Optional SSO wiring — populated by WithSSO / WithPublicBaseURL after NewHandlers.
	ssoProviders  *sso.ProviderStore
	ssoMappings   *sso.MappingStore
	ssoState      *ssostate.Store
	ssoClients    *sso.ClientCache
	ssoEvents     *sso.EventStore
	publicBaseURL string

	// exportBlob is the object-store backend used to serve evidence pack
	// downloads. May be nil in environments that haven't wired up exports
	// (handlers degrade with 503 in that case).
	exportBlob evidence.BlobClient
}

// WithSSO wires the SSO stores onto an existing Handlers.
// Called from server bootstrap after all stores are constructed.
// Passing nil arguments is allowed and disables the SSO surface until
// it is populated (useful for tests that don't exercise SSO).
func (h *Handlers) WithSSO(providers *sso.ProviderStore, mappings *sso.MappingStore, state *ssostate.Store, clients *sso.ClientCache, events *sso.EventStore) *Handlers {
	h.ssoProviders = providers
	h.ssoMappings = mappings
	h.ssoState = state
	h.ssoClients = clients
	h.ssoEvents = events
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

// SetExportBlob wires an evidence pack BlobClient. Called once at startup.
func (h *Handlers) SetExportBlob(b evidence.BlobClient) { h.exportBlob = b }

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	pool *pgxpool.Pool,
	jwtMgr *auth.JWTManager,
	sessions *auth.SessionStore,
	emitter *audit.Emitter,
	js jetstream.JetStream,
	logger zerolog.Logger,
	riskWorker *risk.Worker,
	rbacCache *policy.Cache,
) *Handlers {
	remReg, _ := remediation.LoadBuiltinRegistry()
	return &Handlers{
		pool:        pool,
		jwtMgr:      jwtMgr,
		sessions:    sessions,
		emitter:     emitter,
		js:          js,
		logger:      logger,
		remediation: remReg,
		riskWorker:  riskWorker,
		rbacCache:   rbacCache,
		audit:       emitter,
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
