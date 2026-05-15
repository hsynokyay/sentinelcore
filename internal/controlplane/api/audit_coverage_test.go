package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAuditCoverageMatrix is a static lint: every exported handler method
// on *Handlers whose HTTP semantics are state-changing (POST/PATCH/PUT/
// DELETE routes) must reference the audit emitter. The check walks the
// file that defines each handler and greps for `h.emitter` or h.emit*
// helpers — it does NOT execute the handler.
//
// This is a belt to the braces of actual integration tests (plan §6
// Chunk 8's TestAuditCoverageMatrix in test/integration/ would POST
// every route and assert a row appears). Static detection catches the
// common regression — a handler removing an emit by mistake — in CI
// without standing up a full stack.
//
// Exemptions: handlers listed in `coverageExempt` are known-excluded,
// usually because they are pure read paths that happened to use POST
// for legitimate reasons (e.g. complex filter bodies).
var coverageExempt = map[string]string{
	// Currently empty. Add entries of the form:
	//   "HandlerName": "reason why no audit emit is appropriate",
}

// stateChangingHandlers is the explicit list of handlers that MUST emit.
// Kept as a literal rather than auto-discovered from routes.go so a
// future refactor of routes.go doesn't silently drop a handler from the
// matrix.
var stateChangingHandlers = []string{
	// Phase 6 chunk 8 priority:
	"CreateScan", "CancelScan",
	"UpdateFindingStatus",
	"ResolveRisk", "ReopenRisk", "MuteRisk", "RebuildRisks",
	"CreateAPIKey", "RotateAPIKey", "RevokeAPIKey",
	"CreateSSOProvider", "UpdateSSOProvider", "DeleteSSOProvider",
	"CreateSSOMapping", "DeleteSSOMapping",
	"SSOCallback", "SSOLogout",
	"Login", "Logout",
	"CreateAuditExport",
}

func TestAuditCoverageMatrix(t *testing.T) {
	wd, _ := os.Getwd()
	// Walk all .go files in this package.
	entries, err := os.ReadDir(wd)
	if err != nil {
		t.Fatal(err)
	}

	// Build a map: handler name → source text of its defining file.
	handlerFile := map[string]string{}
	funcRE := regexp.MustCompile(`func\s+\(\s*\w+\s+\*Handlers\s*\)\s+([A-Z]\w+)\s*\(`)
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") ||
			strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(wd, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range funcRE.FindAllStringSubmatch(string(data), -1) {
			handlerFile[m[1]] = string(data)
		}
	}

	// emitPattern matches either h.emitter.Emit, h.audit.Emit, or any
	// h.emitRisk / h.emitProjectScope / h.emitAuditEvent / h.emitAuditSSO
	// helper.
	emitPattern := regexp.MustCompile(`h\.(emitter|audit|emit\w+)`)

	var missing []string
	for _, name := range stateChangingHandlers {
		if reason, ok := coverageExempt[name]; ok {
			t.Logf("exempt: %s — %s", name, reason)
			continue
		}
		src, ok := handlerFile[name]
		if !ok {
			missing = append(missing, name+" (handler not found in package)")
			continue
		}
		// Scope the grep to just the handler's function body. Simple
		// approach: extract from "func (...) Name(" to the next
		// top-level "\nfunc " or EOF.
		start := strings.Index(src, "func (h *Handlers) "+name+"(")
		if start < 0 {
			// Might use a different receiver name.
			start = strings.Index(src, ") "+name+"(")
		}
		if start < 0 {
			missing = append(missing, name+" (locate failed)")
			continue
		}
		end := strings.Index(src[start+1:], "\nfunc ")
		if end < 0 {
			end = len(src) - start - 1
		}
		body := src[start : start+1+end]
		if !emitPattern.MatchString(body) {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		t.Errorf("state-changing handlers without audit emit:\n  %s",
			strings.Join(missing, "\n  "))
	}
}
