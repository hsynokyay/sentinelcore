package bundles

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping store integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	return pool
}

func TestPostgresStore_SaveLoad(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	k := kms.NewLocalProvider([]byte("test-master-key-32-bytes-of-entropy!"))
	store := NewPostgresStore(pool, k, "test-hmac", "alias/test", InlineObjectStore{})

	b := &Bundle{
		ProjectID:       "11111111-1111-1111-1111-111111111111",
		TargetHost:      "app.bank.tld",
		Type:            "session_import",
		CreatedByUserID: "22222222-2222-2222-2222-222222222222",
		CapturedSession: SessionCapture{
			Cookies: []Cookie{{Name: "JSESSIONID", Value: "abc123", Domain: "app.bank.tld", Path: "/"}},
			Headers: map[string]string{"Authorization": "Bearer xyz"},
		},
		TTLSeconds: 3600,
	}
	customerID := "33333333-3333-3333-3333-333333333333"

	id, err := store.Save(context.Background(), b, customerID)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	defer pool.Exec(context.Background(), `DELETE FROM dast_auth_bundles WHERE id=$1`, id)

	loaded, err := store.Load(context.Background(), id, customerID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.TargetHost != "app.bank.tld" {
		t.Errorf("TargetHost: got %q", loaded.TargetHost)
	}
	if len(loaded.CapturedSession.Cookies) != 1 || loaded.CapturedSession.Cookies[0].Name != "JSESSIONID" {
		t.Errorf("Cookies: got %+v", loaded.CapturedSession.Cookies)
	}
	if loaded.CapturedSession.Headers["Authorization"] != "Bearer xyz" {
		t.Errorf("Authorization: got %q", loaded.CapturedSession.Headers["Authorization"])
	}
}

func TestPostgresStore_LoadWrongCustomer(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()

	k := kms.NewLocalProvider([]byte("test-master-key-32-bytes-of-entropy!"))
	store := NewPostgresStore(pool, k, "test-hmac", "alias/test", InlineObjectStore{})

	b := &Bundle{
		ProjectID: "11111111-1111-1111-1111-111111111111",
		TargetHost: "app.bank.tld", Type: "session_import",
		CreatedByUserID: "22222222-2222-2222-2222-222222222222",
		CapturedSession: SessionCapture{Cookies: []Cookie{{Name: "x", Value: "y"}}, Headers: map[string]string{}},
		TTLSeconds: 3600,
	}
	id, _ := store.Save(context.Background(), b, "33333333-3333-3333-3333-333333333333")
	defer pool.Exec(context.Background(), `DELETE FROM dast_auth_bundles WHERE id=$1`, id)

	_, err := store.Load(context.Background(), id, "44444444-4444-4444-4444-444444444444")
	if err == nil {
		t.Fatal("expected error when loading with wrong customer_id")
	}
}
