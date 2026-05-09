package compliance_test

import (
	"context"
	"testing"
)

// TestBuiltinCatalogsPresent asserts migration 025 seeded the three normative
// catalogs and at least one CWE-79 mapping under each.
func TestBuiltinCatalogsPresent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	var n int
	if err := pool.QueryRow(ctx, `
        SELECT count(*) FROM governance.control_catalogs
        WHERE is_builtin = true
          AND code IN ('OWASP_TOP10_2021','PCI_DSS_4_0','NIST_800_53_R5')
    `).Scan(&n); err != nil {
		t.Fatalf("count built-in catalogs: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 built-in catalogs (OWASP/PCI/NIST), got %d", n)
	}

	if err := pool.QueryRow(ctx, `
        SELECT count(*) FROM governance.control_mappings
        WHERE org_id IS NULL AND source_kind='cwe' AND source_code='CWE-79'
    `).Scan(&n); err != nil {
		t.Fatalf("count CWE-79 mappings: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least one built-in CWE-79 mapping, got %d", n)
	}
}

// TestBuiltinOWASPControlsSeeded checks the resolver-relevant OWASP control
// items exist (A01..A10) so the resolver can return CatalogCode/ControlID
// pairs that match what the SARIF/Markdown emitters expect.
func TestBuiltinOWASPControlsSeeded(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	var n int
	if err := pool.QueryRow(ctx, `
        SELECT count(*) FROM governance.control_items i
        JOIN governance.control_catalogs c ON c.id = i.catalog_id
        WHERE c.code = 'OWASP_TOP10_2021'
          AND i.control_id IN ('A01','A02','A03','A04','A05','A06','A07','A08','A09','A10')
    `).Scan(&n); err != nil {
		t.Fatalf("count owasp items: %v", err)
	}
	if n != 10 {
		t.Errorf("expected 10 OWASP A01..A10 items, got %d", n)
	}
}
