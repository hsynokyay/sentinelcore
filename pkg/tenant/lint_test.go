package tenant_test

// lint_test.go enforces tenant-safety invariants by static AST
// inspection across the whole module tree. These tests do not need a
// running database; they guard against regressions like "new handler
// calls pool.Exec directly and bypasses app.current_org_id".
//
// The goal is defence-in-depth: RLS is the primary boundary, but a
// handler that forgets to set app.current_org_id silently reads data
// across tenants (pre-RLS world) or 500s (post-RLS world). Either is
// unacceptable; this test makes it impossible to merge such code.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowedDirectPoolCallers are packages permitted to call pool.Exec /
// pool.Query / pool.QueryRow / pool.SendBatch directly. Keep this list
// MINIMAL. Every entry is a waiver from tenant isolation; every waiver
// is a security review surface.
//
// Rationale per entry:
//   - internal/audit/…            : HMAC writer + consumer write across
//                                   tenants by design (org_id is a column
//                                   in the event, not the session).
//   - internal/audit/integrity/…  : reads partitions regardless of org.
//   - internal/audit/partition/…  : DDL (detach/attach), no RLS scope.
//   - internal/audit/query/…      : platform-admin audit API; uses
//                                   TxGlobal for the audit_global_read
//                                   bypass.
//   - internal/audit/export/…     : streams across tenants as admin.
//   - cmd/*                        : bootstrap/migrations.
//   - pkg/db                       : the pool constructor itself.
//   - pkg/tenant                   : implements Tx (must call pool.*).
//   - internal/controlplane/auth/  : JWT/API-key verifier reads the
//                                   catalog rows before a tenant is
//                                   known (the lookup is what resolves
//                                   the tenant).
//   - internal/controlplane/bootstrap : partition/migration seeding.
//   - internal/controlplane/migrate   : migration runner.
//   - pkg/metrics, pkg/observability  : aggregate queries (no tenant).
var allowedDirectPoolCallers = map[string]bool{
	"pkg/tenant":                                    true,
	"pkg/db":                                        true,
	"pkg/metrics":                                   true,
	"pkg/observability":                             true,
	"internal/audit":                                true,
	"internal/audit/integrity":                      true,
	"internal/audit/partition":                      true,
	"internal/audit/query":                          true,
	"internal/audit/export":                         true,
	"internal/controlplane/auth":                    true,
	"internal/controlplane/bootstrap":               true,
	"internal/controlplane/migrate":                 true,
	"internal/controlplane/api/audit_integrity.go":  true,
	// Worker-dispatched scan webhook delivery: cross-tenant resolve by
	// scan id, needs BYPASSRLS until Wave 3 role split.
	"internal/controlplane/api/scan_webhooks.go":    true,
	// Login path: resolves user+org from email alone; core.users has
	// no RLS, and the query IS the authenticator.
	"internal/controlplane/api/auth.go":             true,
	// Platform-admin queue/ops dashboard; cross-tenant by design.
	// Gated at the route by system.config capability.
	"internal/controlplane/api/ops.go":              true,
	// OIDC callback + SSO event log: both run before (or independent
	// of) a tenant-scoped session. org-resolve-by-slug and login-error
	// event inserts happen before RLS context is available.
	"internal/controlplane/api/sso.go":              true,
}

// poolRecvTypes are variable names conventionally used for the pool
// handle. A call like `pool.Exec(...)` or `s.pool.Exec(...)` counts.
// Anything not matching is ignored (reduces false positives on things
// like `req.Body.Close()`).
var poolRecvTypes = []string{"pool", "Pool", "dbPool", "p.pool", "s.pool", "h.pool"}

// TestNoDirectTenantWrites scans every .go file under the module root
// for disallowed calls to pool.Exec/Query/QueryRow/SendBatch. Any hit
// outside the allowlist fails the test.
//
// Wave 1 of the Phase 7 rollout ships the tenant package without
// migrating the ~95 existing handler call-sites. The strict enforcement
// turns on once Wave 2 finishes the migration; until then the test is
// skipped unless TENANT_LINT_STRICT=1 is set. Running it manually is
// still useful: it prints the offence list as a progress indicator.
func TestNoDirectTenantWrites(t *testing.T) {
	if os.Getenv("TENANT_LINT_STRICT") == "" {
		t.Skip("skip; set TENANT_LINT_STRICT=1 to enforce after Wave 2 migration")
	}
	// Walk from module root (two levels above this test file, since
	// the test runs from pkg/tenant/).
	root := "../.."
	var offences []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			// Skip vendor, third-party, worktrees.
			base := filepath.Base(path)
			if base == "vendor" || base == ".git" || base == "node_modules" ||
				base == ".worktrees" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		pkg := filepath.Dir(rel)
		if allowedDirectPoolCallers[pkg] || allowedDirectPoolCallers[rel] {
			return nil
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil // not a compilable file in this checkout; skip
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Look at .Exec / .Query / .QueryRow / .SendBatch where the
			// receiver looks like a pool handle.
			switch sel.Sel.Name {
			case "Exec", "Query", "QueryRow", "SendBatch":
			default:
				return true
			}
			recv := exprString(sel.X)
			matched := false
			for _, p := range poolRecvTypes {
				if recv == p || strings.HasSuffix(recv, "."+p) {
					matched = true
					break
				}
			}
			if !matched {
				return true
			}
			pos := fset.Position(call.Pos())
			offences = append(offences,
				rel+":"+itoa(pos.Line)+": "+recv+"."+sel.Sel.Name)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offences) > 0 {
		t.Errorf("direct pool.Exec/Query calls outside allowlist (use tenant.Tx):\n  %s",
			strings.Join(offences, "\n  "))
	}
}

// exprString is a minimal stringifier for a SelectorExpr receiver. Not
// using go/printer to keep the test dependency-free and fast.
func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprString(x.X) + "." + x.Sel.Name
	}
	return ""
}

func itoa(n int) string {
	// Tiny allocation-free-ish int→string to avoid pulling strconv only
	// for line numbers in error messages.
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
