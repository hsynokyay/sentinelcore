package apikeys

import (
	"context"
	"testing"
)

func TestRotate_UpdatesHashAndPrefixAtomically(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Seed: create a key.
	in := CreateInput{
		OrgID: testOrgID(t, pool), CreatedBy: testUserID(t, pool), UserID: testUserID(t, pool),
		Name: "rotate-test", Scopes: []string{"risks.read"},
		CreatorPermissions: map[string]struct{}{"risks.read": {}},
		KnownPermissions:   map[string]struct{}{"risks.read": {}},
	}
	created, err := Create(ctx, pool, in)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM core.api_keys WHERE id = $1`, created.ID)
	}()

	oldHash := Hash(created.PlainText)
	oldPrefix := created.Prefix

	// Rotate.
	rotated, err := Rotate(ctx, pool, created.ID, in.OrgID)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if rotated.PlainText == created.PlainText {
		t.Fatal("plaintext should change on rotate")
	}
	if Hash(rotated.PlainText) == oldHash {
		t.Fatal("hash should change")
	}
	if rotated.Prefix == oldPrefix {
		t.Fatal("prefix should change")
	}
	if rotated.OldPrefix != oldPrefix {
		t.Fatalf("OldPrefix=%q, want %q", rotated.OldPrefix, oldPrefix)
	}

	// Old hash is gone — Resolve must return nil key (not found).
	oldRK, err := Resolve(ctx, pool, created.PlainText)
	if err != nil {
		t.Fatalf("Resolve(old) unexpected error: %v", err)
	}
	if oldRK != nil {
		t.Fatal("old plaintext should no longer resolve")
	}
	// New hash resolves.
	newRK, err := Resolve(ctx, pool, rotated.PlainText)
	if err != nil {
		t.Fatalf("new plaintext should resolve: %v", err)
	}
	if newRK == nil {
		t.Fatal("new plaintext resolved to nil")
	}
}

func TestRotate_RejectsWrongOrg(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	in := CreateInput{
		OrgID: testOrgID(t, pool), CreatedBy: testUserID(t, pool), UserID: testUserID(t, pool),
		Name: "rotate-wrong-org-test", Scopes: []string{"risks.read"},
		CreatorPermissions: map[string]struct{}{"risks.read": {}},
		KnownPermissions:   map[string]struct{}{"risks.read": {}},
	}
	created, err := Create(ctx, pool, in)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM core.api_keys WHERE id = $1`, created.ID)
	}()

	// Rotate with a different org ID — tenant isolation must reject.
	if _, err := Rotate(ctx, pool, created.ID, "11111111-1111-1111-1111-111111111111"); err == nil {
		t.Fatal("rotate with wrong org should fail")
	}
}

func TestRotate_RejectsRevokedKey(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	in := CreateInput{
		OrgID: testOrgID(t, pool), CreatedBy: testUserID(t, pool), UserID: testUserID(t, pool),
		Name: "rotate-revoked-test", Scopes: []string{"risks.read"},
		CreatorPermissions: map[string]struct{}{"risks.read": {}},
		KnownPermissions:   map[string]struct{}{"risks.read": {}},
	}
	created, err := Create(ctx, pool, in)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM core.api_keys WHERE id = $1`, created.ID)
	}()

	// Revoke it.
	if _, err := pool.Exec(ctx, `UPDATE core.api_keys SET revoked = true WHERE id = $1`, created.ID); err != nil {
		t.Fatal(err)
	}

	// Rotate should fail.
	if _, err := Rotate(ctx, pool, created.ID, in.OrgID); err == nil {
		t.Fatal("rotate on revoked key should fail")
	}
}
