package sso

import (
	"context"
	"errors"
	"testing"
)

func seedProvider(t *testing.T, s *ProviderStore, orgID string) string {
	t.Helper()
	id, err := s.Create(context.Background(), baseProvider(orgID))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestMappingStore_CreateListDelete(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ms-crud")
	ps := NewProviderStore(pool, testEncryptor(t))
	providerID := seedProvider(t, ps, orgID)

	ms := NewMappingStore(pool)
	ctx := context.Background()

	id1, err := ms.Create(ctx, providerID, "admins", "admin", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ms.Create(ctx, providerID, "auditors", "auditor", 100); err != nil {
		t.Fatal(err)
	}
	got, err := ms.List(ctx, providerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d mappings, want 2", len(got))
	}
	// Priority ASC: admins (1) before auditors (100).
	if got[0].Group != "admins" {
		t.Errorf("ordering: first = %q want admins", got[0].Group)
	}

	if err := ms.Delete(ctx, providerID, id1); err != nil {
		t.Fatal(err)
	}
	if err := ms.Delete(ctx, providerID, id1); !errors.Is(err, ErrMappingNotFound) {
		t.Errorf("double delete: got %v want ErrMappingNotFound", err)
	}
}

func TestMappingStore_UpsertOnConflict(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ms-upsert")
	ps := NewProviderStore(pool, testEncryptor(t))
	providerID := seedProvider(t, ps, orgID)

	ms := NewMappingStore(pool)
	ctx := context.Background()

	id1, err := ms.Create(ctx, providerID, "admins", "developer", 500)
	if err != nil {
		t.Fatal(err)
	}
	// Same group, new role+priority → updates in place, keeps id.
	id2, err := ms.Create(ctx, providerID, "admins", "admin", 1)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Errorf("upsert should preserve id: id1=%s id2=%s", id1, id2)
	}
	list, _ := ms.List(ctx, providerID)
	if len(list) != 1 || list[0].Role != "admin" || list[0].Priority != 1 {
		t.Errorf("upsert didn't update: %+v", list)
	}
}

func TestMappingStore_ListForResolver(t *testing.T) {
	pool := testPool(t)
	orgID := seedOrg(t, pool, "ms-resolver")
	ps := NewProviderStore(pool, testEncryptor(t))
	providerID := seedProvider(t, ps, orgID)

	ms := NewMappingStore(pool)
	ctx := context.Background()

	_, _ = ms.Create(ctx, providerID, "admins", "admin", 1)
	_, _ = ms.Create(ctx, providerID, "sec-engs", "security_engineer", 10)

	mappings, err := ms.ListForResolver(ctx, providerID)
	if err != nil {
		t.Fatal(err)
	}
	// ListForResolver returns GroupMapping (not StoredMapping) — fuel for ResolveRole.
	got, ok := ResolveRole([]string{"admins", "sec-engs"}, mappings, "developer")
	if !ok || got != "admin" {
		t.Errorf("resolver over store: got %q ok=%v want admin/true", got, ok)
	}
}
