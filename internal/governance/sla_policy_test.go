package governance_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/governance"
)

// TestResolveSLADays_FallbackDefaultsWhenNoOrgSettings exercises the fallback
// path when no org_settings row and no project policy exist. With no
// TEST_DATABASE_URL set the test simply skips via testPool.
func TestResolveSLADays_FallbackDefaultsWhenNoOrgSettings(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Random IDs that do not exist anywhere — both queries should miss and
	// the helper should fall back to the package defaults.
	orgID := uuid.New()
	projID := uuid.New()

	days, err := governance.ResolveSLADays(ctx, pool, orgID, projID)
	if err != nil {
		t.Fatalf("ResolveSLADays: %v", err)
	}
	if days["high"] != 7 || days["critical"] != 3 || days["medium"] != 30 || days["low"] != 90 {
		t.Errorf("expected default SLA days, got %v", days)
	}
}

// TestResolveSLADays_ProjectOverridesOrg seeds an org with custom SLA defaults
// then a project-level override and asserts precedence: project > org > default.
func TestResolveSLADays_ProjectOverridesOrg(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	orgID, projID, cleanup := seedOrgAndProject(t, pool, "standard")
	t.Cleanup(cleanup)

	// Org default already seeded by seedOrgAndProject (uses default 3/7/30/90).
	days, err := governance.ResolveSLADays(ctx, pool, orgID, projID)
	if err != nil {
		t.Fatalf("ResolveSLADays org-default: %v", err)
	}
	if got := days["high"]; got != 7 {
		t.Errorf("org-default high: expected 7, got %d", got)
	}

	// Insert a project override and re-resolve.
	user := seedUser(t, pool, orgID, "security_admin")
	override := map[string]int{"critical": 1, "high": 3, "medium": 14, "low": 60}
	raw, _ := json.Marshal(override)
	if _, err := pool.Exec(ctx, `
		INSERT INTO governance.project_sla_policies (org_id, project_id, sla_days, updated_by)
		VALUES ($1, $2, $3, $4)
	`, orgID, projID, raw, user); err != nil {
		t.Fatalf("insert project_sla_policies: %v", err)
	}

	days, err = governance.ResolveSLADays(ctx, pool, orgID, projID)
	if err != nil {
		t.Fatalf("ResolveSLADays project-override: %v", err)
	}
	if got := days["high"]; got != 3 {
		t.Errorf("project-override high: expected 3, got %d", got)
	}
	if got := days["critical"]; got != 1 {
		t.Errorf("project-override critical: expected 1, got %d", got)
	}
}
