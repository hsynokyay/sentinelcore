package dast

import (
	"encoding/json"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/crypto"
)

// TestResolveAuthConfig verifies that an encrypted secret + metadata row from
// auth.auth_configs decrypts and resolves into an authbroker.AuthConfig with
// the right strategy + credentials shape for each supported auth type.
func TestResolveAuthConfig(t *testing.T) {
	key := make([]byte, crypto.AESGCMKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, err := crypto.NewAESGCM(key)
	if err != nil {
		t.Fatalf("init cipher: %v", err)
	}

	projectID := "11111111-1111-1111-1111-111111111111"

	cases := []struct {
		name             string
		authType         string
		secret           string
		metadata         map[string]any
		wantStrategy     string
		wantCredKey      string
		wantCredVal      string
		wantExtraName    string
		wantExtraNameKey string
		wantEndpoint     string
	}{
		{
			name:         "bearer_token resolves to bearer strategy with token credential",
			authType:     "bearer_token",
			secret:       "eyJhbGciOiJIUzI1NiJ9.payload.sig",
			metadata:     map[string]any{"token_prefix": "Bearer"},
			wantStrategy: "bearer",
			wantCredKey:  "token",
			wantCredVal:  "eyJhbGciOiJIUzI1NiJ9.payload.sig",
		},
		{
			name:             "api_key (header) resolves to api_key strategy with header location",
			authType:         "api_key",
			secret:           "sk-live-abc123",
			metadata:         map[string]any{"header_name": "X-Custom-Key"},
			wantStrategy:     "api_key",
			wantCredKey:      "api_key",
			wantCredVal:      "sk-live-abc123",
			wantExtraNameKey: "name",
			wantExtraName:    "X-Custom-Key",
		},
		{
			name:         "basic_auth resolves to basic strategy with username + password credentials",
			authType:     "basic_auth",
			secret:       "p4ssw0rd",
			metadata:     map[string]any{"username": "admin"},
			wantStrategy: "basic",
			wantCredKey:  "password",
			wantCredVal:  "p4ssw0rd",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := cipher.Seal([]byte(tc.secret), []byte(projectID))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}

			metaJSON, _ := json.Marshal(tc.metadata)
			cfg, err := ResolveAuthConfig(cipher, projectID, tc.authType, ciphertext, metaJSON)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}

			if cfg.Strategy != tc.wantStrategy {
				t.Errorf("strategy = %q, want %q", cfg.Strategy, tc.wantStrategy)
			}
			if got := cfg.Credentials[tc.wantCredKey]; got != tc.wantCredVal {
				t.Errorf("credentials[%q] = %q, want %q", tc.wantCredKey, got, tc.wantCredVal)
			}
			if tc.wantExtraNameKey != "" {
				if got := cfg.ExtraParams[tc.wantExtraNameKey]; got != tc.wantExtraName {
					t.Errorf("extra[%q] = %q, want %q", tc.wantExtraNameKey, got, tc.wantExtraName)
				}
			}
			if tc.authType == "basic_auth" {
				if cfg.Credentials["username"] != "admin" {
					t.Errorf("basic_auth username = %q, want admin", cfg.Credentials["username"])
				}
			}
		})
	}
}

// TestResolveAuthConfig_WrongProjectID rejects ciphertext bound to a different
// project — defense against blob theft / cross-project replay.
func TestResolveAuthConfig_WrongProjectID(t *testing.T) {
	key := make([]byte, crypto.AESGCMKeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cipher, _ := crypto.NewAESGCM(key)

	ciphertext, _ := cipher.Seal([]byte("secret"), []byte("project-A"))
	metaJSON := []byte(`{"token_prefix":"Bearer"}`)

	if _, err := ResolveAuthConfig(cipher, "project-B", "bearer_token", ciphertext, metaJSON); err == nil {
		t.Fatal("expected decrypt failure for wrong project_id binding, got nil")
	}
}

// TestResolveAuthConfig_UnsupportedType returns an explicit error so callers
// don't silently dispatch with a zero AuthConfig.
func TestResolveAuthConfig_UnsupportedType(t *testing.T) {
	key := make([]byte, crypto.AESGCMKeyLen)
	cipher, _ := crypto.NewAESGCM(key)

	_, err := ResolveAuthConfig(cipher, "p", "saml", []byte{}, []byte("{}"))
	if err == nil {
		t.Fatal("expected error for unsupported auth_type, got nil")
	}
}
