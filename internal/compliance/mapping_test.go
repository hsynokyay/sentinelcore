package compliance_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/compliance"
)

// testPool returns a pgxpool connected to TEST_DATABASE_URL or skips the test.
// Migrations 024 and 025 must already be applied by the test harness.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping compliance integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// seedOrg inserts an isolated organization and returns its UUID plus a
// cleanup callback. Custom catalogs/items/mappings are FK-cascaded via
// the catalog row (ON DELETE CASCADE), so we only need to drop the org.
func seedOrg(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, func()) {
	t.Helper()
	ctx := context.Background()
	orgID := uuid.New()
	suffix := orgID.String()[:8]
	if _, err := pool.Exec(ctx, `
        INSERT INTO core.organizations (id, name, display_name, created_at, updated_at)
        VALUES ($1, $2, $3, now(), now())
    `, orgID, "compliance-org-"+suffix, "Compliance Org "+suffix); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM governance.control_mappings WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM governance.control_catalogs WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.organizations WHERE id = $1`, orgID)
	}
	return orgID, cleanup
}

// seedCustomCatalog inserts a tenant-owned catalog and returns its id.
func seedCustomCatalog(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, code, version string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), `
        INSERT INTO governance.control_catalogs (id, org_id, code, name, version, is_builtin)
        VALUES ($1, $2, $3, $4, $5, false)
    `, id, orgID, code, code+" custom", version); err != nil {
		t.Fatalf("seed custom catalog: %v", err)
	}
	return id
}

// seedCustomItem inserts a tenant-owned item under the given catalog.
func seedCustomItem(t *testing.T, pool *pgxpool.Pool, catalogID uuid.UUID, controlID, title string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), `
        INSERT INTO governance.control_items (id, catalog_id, control_id, title)
        VALUES ($1, $2, $3, $4)
    `, id, catalogID, controlID, title); err != nil {
		t.Fatalf("seed custom item: %v", err)
	}
	return id
}

// seedCustomMapping inserts a tenant-owned mapping.
func seedCustomMapping(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, sourceKind, sourceCode string, targetItemID uuid.UUID, confidence string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
        INSERT INTO governance.control_mappings
            (org_id, source_kind, source_code, target_control_id, confidence)
        VALUES ($1, $2, $3, $4, $5)
    `, orgID, sourceKind, sourceCode, targetItemID, confidence); err != nil {
		t.Fatalf("seed custom mapping: %v", err)
	}
}

// TestResolveControls_MergesBuiltinAndCustom is the headline contract test
// for Epic C: built-in CWE-79 → OWASP A03 mappings (from migration 025)
// must surface for every org, and a tenant-added custom mapping must
// merge into the same resolver call without leaking to other orgs.
func TestResolveControls_MergesBuiltinAndCustom(t *testing.T) {
	pool := testPool(t)
	orgID, cleanup := seedOrg(t, pool)
	defer cleanup()
	ctx := context.Background()

	// Built-in mapping check (depends on seed migration 025).
	refs, err := compliance.ResolveControls(ctx, pool, orgID, 79)
	if err != nil {
		t.Fatalf("ResolveControls (built-in only): %v", err)
	}
	var owasp string
	for _, r := range refs {
		if r.CatalogCode == "OWASP_TOP10_2021" {
			owasp = r.ControlID
			break
		}
	}
	if owasp != "A03" {
		t.Fatalf("expected built-in CWE-79 → OWASP A03, got refs=%+v", refs)
	}

	// Tenant custom mapping merges in.
	customCat := seedCustomCatalog(t, pool, orgID, "INTERNAL_SEC", "1.0")
	itemID := seedCustomItem(t, pool, customCat, "SEC-007", "Secure output encoding")
	seedCustomMapping(t, pool, orgID, "cwe", "CWE-79", itemID, "custom")

	refs, err = compliance.ResolveControls(ctx, pool, orgID, 79)
	if err != nil {
		t.Fatalf("ResolveControls (with custom): %v", err)
	}
	var hasCustom bool
	for _, r := range refs {
		if r.ControlID == "SEC-007" && r.Confidence == "custom" {
			hasCustom = true
			break
		}
	}
	if !hasCustom {
		t.Fatalf("expected custom SEC-007 mapping in refs, got %+v", refs)
	}

	// Custom rows must come first thanks to the deterministic ordering.
	if refs[0].Confidence != "custom" {
		t.Errorf("expected first ref to be custom-confidence, got %q (refs=%+v)", refs[0].Confidence, refs)
	}
}

// TestResolveControls_NoLeakAcrossOrgs ensures a tenant's custom mapping
// is invisible to other orgs even though they all see the built-ins.
func TestResolveControls_NoLeakAcrossOrgs(t *testing.T) {
	pool := testPool(t)
	orgA, cleanupA := seedOrg(t, pool)
	defer cleanupA()
	orgB, cleanupB := seedOrg(t, pool)
	defer cleanupB()
	ctx := context.Background()

	customCat := seedCustomCatalog(t, pool, orgA, "ORG_A_SEC", "1.0")
	itemID := seedCustomItem(t, pool, customCat, "A-OWN-1", "Org A only")
	seedCustomMapping(t, pool, orgA, "cwe", "CWE-89", itemID, "custom")

	refsB, err := compliance.ResolveControls(ctx, pool, orgB, 89)
	if err != nil {
		t.Fatalf("ResolveControls org B: %v", err)
	}
	for _, r := range refsB {
		if r.ControlID == "A-OWN-1" {
			t.Fatalf("org B leaked org A's custom mapping: %+v", r)
		}
	}
}
