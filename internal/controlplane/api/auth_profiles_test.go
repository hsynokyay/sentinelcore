package api

import (
	"testing"
	"time"
)

func TestBuildMetadataAndSecret(t *testing.T) {
	cases := []struct {
		name        string
		req         authProfileRequest
		wantErr     bool
		wantSecret  string
		wantHeader  string
		wantQuery   string
		wantPrefix  string
		wantUser    string
		wantErrHint string
	}{
		{
			name: "bearer_token default prefix",
			req: authProfileRequest{
				AuthType: "bearer_token",
				Token:    "abc123",
			},
			wantSecret: "abc123",
			wantPrefix: "Bearer",
		},
		{
			name: "bearer_token custom prefix",
			req: authProfileRequest{
				AuthType:    "bearer_token",
				Token:       "abc",
				TokenPrefix: "Token",
			},
			wantSecret: "abc",
			wantPrefix: "Token",
		},
		{
			name:    "bearer_token missing token",
			req:     authProfileRequest{AuthType: "bearer_token"},
			wantErr: true,
		},
		{
			name: "api_key default header",
			req: authProfileRequest{
				AuthType: "api_key",
				APIKey:   "sk-live-xxx",
			},
			wantSecret: "sk-live-xxx",
			wantHeader: "X-API-Key",
		},
		{
			name: "api_key with custom header",
			req: authProfileRequest{
				AuthType:   "api_key",
				APIKey:     "k",
				HeaderName: "Authorization",
			},
			wantSecret: "k",
			wantHeader: "Authorization",
		},
		{
			name: "api_key with query name",
			req: authProfileRequest{
				AuthType:  "api_key",
				APIKey:    "k",
				QueryName: "token",
			},
			wantSecret: "k",
			wantQuery:  "token",
		},
		{
			name: "api_key rejects both header and query",
			req: authProfileRequest{
				AuthType:   "api_key",
				APIKey:     "k",
				HeaderName: "X",
				QueryName:  "q",
			},
			wantErr: true,
		},
		{
			name:    "api_key missing key",
			req:     authProfileRequest{AuthType: "api_key"},
			wantErr: true,
		},
		{
			name: "basic_auth ok",
			req: authProfileRequest{
				AuthType: "basic_auth",
				Username: "alice",
				Password: "hunter2",
			},
			wantSecret: "hunter2",
			wantUser:   "alice",
		},
		{
			name:    "basic_auth missing password",
			req:     authProfileRequest{AuthType: "basic_auth", Username: "alice"},
			wantErr: true,
		},
		{
			name:    "unknown auth_type",
			req:     authProfileRequest{AuthType: "telepathy"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta, secret, errMsg := buildMetadataAndSecret(&tc.req)
			if tc.wantErr {
				if errMsg == "" {
					t.Fatalf("expected error, got meta=%v secret=%s", meta, string(secret))
				}
				return
			}
			if errMsg != "" {
				t.Fatalf("unexpected error: %s", errMsg)
			}
			if string(secret) != tc.wantSecret {
				t.Errorf("secret = %q, want %q", string(secret), tc.wantSecret)
			}
			if tc.wantHeader != "" && meta["header_name"] != tc.wantHeader {
				t.Errorf("header_name = %v, want %q", meta["header_name"], tc.wantHeader)
			}
			if tc.wantQuery != "" && meta["query_name"] != tc.wantQuery {
				t.Errorf("query_name = %v, want %q", meta["query_name"], tc.wantQuery)
			}
			if tc.wantPrefix != "" && meta["token_prefix"] != tc.wantPrefix {
				t.Errorf("token_prefix = %v, want %q", meta["token_prefix"], tc.wantPrefix)
			}
			if tc.wantUser != "" && meta["username"] != tc.wantUser {
				t.Errorf("username = %v, want %q", meta["username"], tc.wantUser)
			}
			// Sanity: metadata must never contain the actual secret value.
			for _, forbidden := range []string{"token", "api_key", "password"} {
				if _, ok := meta[forbidden]; ok {
					t.Errorf("metadata unexpectedly contains %q — it should only be in encrypted_secret", forbidden)
				}
			}
		})
	}
}

func TestValidateSafeURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://api.example.com/login", false},
		{"http://api.example.com/login", false},
		{"ftp://api.example.com/login", true},
		{"not-a-url", true},
		{"", true},
		{"http://127.0.0.1/login", true},
		{"http://169.254.169.254/latest/meta-data", true}, // cloud metadata IP
		{"http://10.0.0.1/login", true},
		{"http://192.168.1.1/login", true},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			e := validateSafeURL(tc.url)
			if tc.wantErr && e == "" {
				t.Errorf("expected error for %q", tc.url)
			}
			if !tc.wantErr && e != "" {
				t.Errorf("unexpected error for %q: %s", tc.url, e)
			}
		})
	}
}

func TestRowToProfileResponseNeverLeaksSecret(t *testing.T) {
	// Contract test: the public response shape should never carry any field
	// that could hold ciphertext or plaintext secret material. Metadata that
	// accidentally included such a field would be a critical regression.
	metadata := []byte(`{"header_name":"X-API-Key"}`)
	now := time.Now().UTC()
	resp := rowToProfileResponse(
		"id1", "pid1", "my-profile", "api_key", "test",
		"user-1", metadata, true,
		now, now,
	)
	if !resp.HasCredentials {
		t.Errorf("HasCredentials should be true")
	}
	for _, forbidden := range []string{"token", "api_key", "password", "encrypted_secret"} {
		if _, ok := resp.Metadata[forbidden]; ok {
			t.Errorf("metadata must not contain %q", forbidden)
		}
	}
}
