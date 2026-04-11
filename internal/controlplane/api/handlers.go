package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/remediation"
	"github.com/sentinelcore/sentinelcore/internal/risk"
	"github.com/sentinelcore/sentinelcore/pkg/audit"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
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
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	pool *pgxpool.Pool,
	jwtMgr *auth.JWTManager,
	sessions *auth.SessionStore,
	emitter *audit.Emitter,
	js jetstream.JetStream,
	logger zerolog.Logger,
	riskWorker *risk.Worker,
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
