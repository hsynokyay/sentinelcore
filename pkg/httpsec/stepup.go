package httpsec

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// ReauthLookup is the SessionStore contract needed by RequireStepUp.
// Declared as an interface so the middleware doesn't depend on the
// concrete pkg/auth type (and so tests can pass a fake).
type ReauthLookup interface {
	LastReauth(ctx context.Context, jti string) (time.Time, error)
}

// PrincipalFromCtx extracts the authenticated principal's JTI from
// the request context. The caller wires this via StepUpConfig so
// that httpsec does not depend on pkg/auth directly.
type PrincipalFromCtx func(ctx context.Context) (jti string, ok bool)

// StepUpConfig wires the middleware to an app-specific session store
// and JTI extractor.
type StepUpConfig struct {
	Sessions     ReauthLookup
	GetJTI       PrincipalFromCtx
	MaxAge       time.Duration // how recent a reauth must be; default 5 min
	ErrorWriter  func(w http.ResponseWriter, status int, msg, code string)
}

// RequireStepUp returns middleware that refuses to let a request
// reach the wrapped handler unless the session's last_reauth
// timestamp is within MaxAge of now.
//
// Intended for destructive/admin routes:
//
//   mux.Handle("DELETE /users/{id}", httpsec.RequireStepUp(cfg)(handler))
//
// Response on failure: 403 with JSON body {"code":"STEP_UP_REQUIRED"}.
// The frontend catches this and pops the re-enter-password dialog.
func RequireStepUp(cfg StepUpConfig) func(http.Handler) http.Handler {
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 5 * time.Minute
	}
	if cfg.ErrorWriter == nil {
		cfg.ErrorWriter = defaultErrorWriter
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jti, ok := cfg.GetJTI(r.Context())
			if !ok || jti == "" {
				// Not authenticated — auth middleware should have caught
				// this earlier. Fail-safe: reject.
				cfg.ErrorWriter(w, http.StatusUnauthorized,
					"authentication required", "UNAUTHORIZED")
				return
			}
			last, err := cfg.Sessions.LastReauth(r.Context(), jti)
			if err != nil {
				// Redis outage: fail CLOSED on admin paths. Better to
				// refuse destructive operations than to silently allow
				// them when we can't prove a recent reauth.
				cfg.ErrorWriter(w, http.StatusServiceUnavailable,
					"session store unavailable", "SESSION_UNAVAILABLE")
				return
			}
			if last.IsZero() || time.Since(last) > cfg.MaxAge {
				cfg.ErrorWriter(w, http.StatusForbidden,
					"recent re-authentication required", "STEP_UP_REQUIRED")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ErrStepUpRequired mirrors the response code so server-side code
// can `errors.Is(err, ErrStepUpRequired)` against a generated error
// from a helper that doesn't write an HTTP response itself.
var ErrStepUpRequired = errors.New("httpsec: step-up re-authentication required")

// defaultErrorWriter emits a minimal JSON body. Handlers that need
// a richer shape should pass their own via StepUpConfig.ErrorWriter.
func defaultErrorWriter(w http.ResponseWriter, status int, msg, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Minimal envelope matching internal/controlplane/api.writeError.
	_, _ = w.Write([]byte(`{"error":"` + msg + `","code":"` + code + `"}`))
}
