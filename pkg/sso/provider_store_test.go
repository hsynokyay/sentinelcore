package sso

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/crypto/aesgcm"
)

// testPool returns a pgxpool against TEST_DATABASE_URL, or skips.
// Caller is responsible for rolling back via t.Cleanup.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func testEncryptor(t *testing.T) *aesgcm.Encryptor {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	e, err := aesgcm.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// seedOrg inserts a test organization and returns its ID + slug. Uses
// deterministic slug so subsequent tests can find it. Caller is
// responsible for cleanup (tests run sequentially and tear down via
// ON DELETE CASCADE when the org row is removed).
func seedOrg(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO core.organizations (name, slug)
		VALUES ($1, $2)
		ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		RETURNING id::text
	`, "Test "+slug, slug).Scan(&id)
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM core.organizations WHERE id = $1`, id)
	})
	return id
}

func baseProvider(orgID string) Provider {
	return Provider{
		OrgID:            orgID,
		ProviderSlug:     "keycloak-test",
		DisplayName:      "Keycloak (test)",
		IssuerURL:        "https://kc.example.com/realms/main",
		ClientID:         "sentinelcore",
		ClientSecret:     "top-secret-value",
		Scopes:           []string{"openid", "email", "profile", "groups"},
		DefaultRoleID:    "developer",
		SyncRoleOnLogin:  true,
		SSOLogoutEnabled: false,
		Enabled:          true,
	}
}

func TestProviderStore_CreateAndGet(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ps-create-get")
	s := NewProviderStore(pool, testEncryptor(t))

	id, err := s.Create(context.Background(), baseProvider(orgID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ClientSecret != "top-secret-value" {
		t.Errorf("secret roundtrip: got %q", got.ClientSecret)
	}
	if got.DisplayName != "Keycloak (test)" {
		t.Errorf("display_name: got %q", got.DisplayName)
	}
}

func TestProviderStore_List_OmitsSecret(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ps-list")
	s := NewProviderStore(pool, testEncryptor(t))

	if _, err := s.Create(context.Background(), baseProvider(orgID)); err != nil {
		t.Fatal(err)
	}
	// List does NOT select client_secret; the struct's ClientSecret
	// field must remain its zero value.
	providers, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range providers {
		if p.OrgID == orgID {
			found = true
			if p.ClientSecret != "" {
				t.Errorf("List must not populate ClientSecret, got %q", p.ClientSecret)
			}
		}
	}
	if !found {
		t.Fatal("inserted provider not found in list")
	}
}

func TestProviderStore_Update_PreservesSecret(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ps-update-preserve")
	s := NewProviderStore(pool, testEncryptor(t))
	ctx := context.Background()

	id, err := s.Create(ctx, baseProvider(orgID))
	if err != nil {
		t.Fatal(err)
	}
	p := baseProvider(orgID)
	p.DisplayName = "Keycloak v2"
	// newSecret = "" → preserve existing
	if err := s.Update(ctx, id, p, ""); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Keycloak v2" {
		t.Errorf("display_name: got %q want Keycloak v2", got.DisplayName)
	}
	if got.ClientSecret != "top-secret-value" {
		t.Errorf("secret should be preserved, got %q", got.ClientSecret)
	}
}

func TestProviderStore_Update_RotatesSecret(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ps-update-rotate")
	s := NewProviderStore(pool, testEncryptor(t))
	ctx := context.Background()

	id, err := s.Create(ctx, baseProvider(orgID))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, id, baseProvider(orgID), "rotated-secret"); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientSecret != "rotated-secret" {
		t.Errorf("secret: got %q want rotated-secret", got.ClientSecret)
	}
}

func TestProviderStore_GetByOrgSlug_OnlyEnabled(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ps-slug-enabled")
	s := NewProviderStore(pool, testEncryptor(t))
	ctx := context.Background()

	p := baseProvider(orgID)
	p.Enabled = false
	if _, err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	_, err := s.GetByOrgSlug(ctx, "ps-slug-enabled", p.ProviderSlug)
	if !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("disabled provider should be invisible to GetByOrgSlug, got %v", err)
	}
}

func TestProviderStore_Delete(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ps-delete")
	s := NewProviderStore(pool, testEncryptor(t))
	ctx := context.Background()

	id, err := s.Create(ctx, baseProvider(orgID))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("after Delete Get should be ErrProviderNotFound, got %v", err)
	}
	if err := s.Delete(ctx, id); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("double Delete should be ErrProviderNotFound, got %v", err)
	}
}
