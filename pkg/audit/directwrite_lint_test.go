package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoDirectAuditLogWrites asserts that no Go source file in the
// repository contains a SQL statement writing to audit.audit_log or its
// sibling tables outside of the sanctioned write path.
//
// Sanctioned paths — only these may touch the tables with SQL:
//
//   - internal/audit/           (Writer + HMACWriter + Consumer)
//   - internal/audit/integrity/ (Verifier + Scheduler — writes to integrity_checks)
//   - migrations/               (schema)
//
// Everywhere else must use pkg/audit.Emitter.Emit(). Direct SQL on the
// audit tables bypasses the HMAC chain and the append-only trigger
// (triggers fire on UPDATE/DELETE but an INSERT with previous_hash='' /
// entry_hash='' would appear legitimate). CI catching this at source
// is the last line of defence.
func TestNoDirectAuditLogWrites(t *testing.T) {
	// Walk up from pkg/audit to the repo root.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))

	// Patterns that WRITE to audit tables. Intentionally case-sensitive
	// and narrow: SELECT queries are fine (some handlers will read audit
	// rows in chunk 7's export pipeline).
	writePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)INSERT\s+INTO\s+audit\.audit_log\b`),
		regexp.MustCompile(`(?i)INSERT\s+INTO\s+audit\.risk_events\b`),
		regexp.MustCompile(`(?i)INSERT\s+INTO\s+audit\.integrity_checks\b`),
		regexp.MustCompile(`(?i)UPDATE\s+audit\.audit_log\b`),
		regexp.MustCompile(`(?i)DELETE\s+FROM\s+audit\.audit_log\b`),
	}

	// Path segments that are ALLOWED to contain these patterns. Match is
	// by substring on the file's path (forward-slash normalized).
	allowed := []string{
		"/internal/audit/",
		"/internal/audit/integrity/",
		"/migrations/",
		"/pkg/audit/", // this test file itself mentions the patterns
		// Role-split integration tests assert that writes to audit
		// tables from specific DB roles are REJECTED — the SQL
		// string appears as a test probe, not a live write.
		"/test/integration/role_split_test.go",
	}

	var violations []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			// Skip expensive irrelevant dirs.
			name := info.Name()
			if name == "node_modules" || name == ".next" || name == ".git" ||
				name == ".worktrees" || name == "web" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		norm := filepath.ToSlash(path)
		for _, ok := range allowed {
			if strings.Contains(norm, ok) {
				return nil
			}
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, pat := range writePatterns {
			if pat.Match(data) {
				rel, _ := filepath.Rel(root, path)
				violations = append(violations,
					rel+" matches forbidden pattern: "+pat.String())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(violations) > 0 {
		t.Errorf("direct audit-table writes found outside sanctioned paths:\n  %s",
			strings.Join(violations, "\n  "))
	}
}
