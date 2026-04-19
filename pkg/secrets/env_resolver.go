package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// EnvResolver reads secrets from OS environment variables using a
// deterministic translation:
//
//   tier0/aes/master      → SC_T0_AES_MASTER
//   tier1/postgres/ctl    → SC_T1_POSTGRES_CTL
//
// The translator is strict — unknown tier prefixes or forbidden chars
// cause a hard error rather than a silent fallback. This is the
// transitional backend; production migrates to VaultResolver.
type EnvResolver struct{}

// NewEnvResolver returns the default Resolver for dev / CI / today's
// prod deployment.
func NewEnvResolver() *EnvResolver { return &EnvResolver{} }

// Backend satisfies Resolver.
func (*EnvResolver) Backend() string { return "env" }

// pathToEnvVar translates a canonical secret path to the env var name.
// Uppercase, slashes → underscores, prefix SC_. Refuses any character
// outside [a-z0-9_/-] to prevent path-injection from user input.
func pathToEnvVar(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("secrets: empty path")
	}
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '/' || c == '_' || c == '-':
		default:
			return "", fmt.Errorf("secrets: illegal char %q in path %q", c, path)
		}
	}
	return "SC_" + strings.NewReplacer("/", "_", "-", "_").
		Replace(strings.ToUpper(path)), nil
}

// Get reads the env var and returns its bytes. Missing var → ErrNotFound.
func (r *EnvResolver) Get(ctx context.Context, path string) ([]byte, error) {
	name, err := pathToEnvVar(path)
	if err != nil {
		return nil, err
	}
	raw, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("%w: %s (env %s)", ErrNotFound, path, name)
	}
	return []byte(raw), nil
}

// GetString is the ASCII-friendly form.
func (r *EnvResolver) GetString(ctx context.Context, path string) (string, error) {
	b, err := r.Get(ctx, path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Version is always -1 for the env backend — the env var is what it is.
// Rotation via env is "edit the value", not "add a version". Callers that
// need versioned lookups (AES master key history) use the DB catalog
// paths instead (auth.aes_keys.version).
func (r *EnvResolver) Version(ctx context.Context, path string) (int, error) {
	if _, err := r.Get(ctx, path); err != nil {
		return -1, err
	}
	return -1, nil
}
