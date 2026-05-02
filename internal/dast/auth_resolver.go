package dast

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	"github.com/sentinelcore/sentinelcore/pkg/crypto"
)

// ResolveAuthConfig decrypts an `auth.auth_configs` row's encrypted_secret blob
// (AES-256-GCM keyed by AUTH_PROFILE_ENCRYPTION_KEY, AAD = project_id) and
// builds an authbroker.AuthConfig ready for the broker's CreateSession.
//
// authType, ciphertext, and configJSON come straight from the DB row:
//
//	SELECT auth_type, encrypted_secret, config FROM auth.auth_configs WHERE id = $1
//
// configJSON is the public metadata blob (token_prefix, header_name, username,
// endpoint_url) — never sensitive. The secret payload is whatever
// buildMetadataAndSecret in controlplane stored:
//
//   - bearer_token  → raw token bytes
//   - api_key       → raw key bytes
//   - basic_auth    → password bytes (username lives in metadata)
func ResolveAuthConfig(
	cipher *crypto.AESGCM,
	projectID, authType string,
	ciphertext, configJSON []byte,
) (*authbroker.AuthConfig, error) {
	if cipher == nil {
		return nil, errors.New("auth resolver: nil cipher")
	}

	plaintext, err := cipher.Open(ciphertext, []byte(projectID))
	if err != nil {
		return nil, fmt.Errorf("auth resolver: decrypt failed (project_id binding mismatch?): %w", err)
	}

	var metadata map[string]any
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &metadata); err != nil {
			return nil, fmt.Errorf("auth resolver: invalid metadata JSON: %w", err)
		}
	}
	if metadata == nil {
		metadata = map[string]any{}
	}

	cfg := &authbroker.AuthConfig{
		Credentials: map[string]string{},
		ExtraParams: map[string]string{},
	}

	// endpoint_url is shared metadata across all auth types (e.g. for OAuth).
	if v, ok := metadata["endpoint_url"].(string); ok {
		cfg.Endpoint = v
	}

	switch authType {
	case "bearer_token":
		cfg.Strategy = "bearer"
		cfg.Credentials["token"] = string(plaintext)
	case "api_key":
		cfg.Strategy = "api_key"
		cfg.Credentials["api_key"] = string(plaintext)
		// Header location is the only one supported via metadata today.
		// Query-string keys could be added later by reading metadata["query_name"].
		if name, ok := metadata["header_name"].(string); ok && name != "" {
			cfg.ExtraParams["location"] = "header"
			cfg.ExtraParams["name"] = name
		}
	case "basic_auth":
		cfg.Strategy = "basic"
		user, _ := metadata["username"].(string)
		if user == "" {
			return nil, errors.New("auth resolver: basic_auth missing username in metadata")
		}
		cfg.Credentials["username"] = user
		cfg.Credentials["password"] = string(plaintext)
	default:
		return nil, fmt.Errorf("auth resolver: unsupported auth_type %q", authType)
	}

	return cfg, nil
}
