package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Fingerprint builds a stable 64-char hex identifier for a finding that
// survives cosmetic source changes (whitespace, local variable renames,
// import reordering) and is identical across scans of the same logical
// location. This is what lets the triage pipeline preserve assignee,
// status, legal hold, and SLA state across scans.
//
// The fingerprint is a SHA-256 of the tuple:
//
//   rule_id || module_path || containing_function_fqn || callee_fqn || key_arg
//
// where key_arg is the first constant-string operand at the sink location
// (e.g. "DES" for a weak crypto finding) or the empty string if there is
// none. We deliberately do NOT include the line number — a finding that
// moves to a different line because imports were reorganized should match
// the same fingerprint so triage state is preserved.
//
// Later chunks that add taint findings will extend this with a semantic
// hash of the AST shape at source and sink locations, so "req.getParameter"
// on different parameter names collapses to the same fingerprint. For
// Chunk SAST-1 the simple form above is sufficient.
func Fingerprint(ruleID, modulePath, functionFQN, calleeFQN, keyArg string) string {
	parts := []string{
		"v1",
		ruleID,
		modulePath,
		functionFQN,
		calleeFQN,
		keyArg,
	}
	data := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
