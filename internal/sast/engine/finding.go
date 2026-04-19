// Package engine is the SentinelCore SAST analysis core. It consumes
// SentinelIR modules, applies compiled rules, and emits Findings with
// evidence chains. It is intentionally independent of the findings database
// schema — emitting findings into findings.findings is the job of a thin
// adapter in the worker (later chunk).
package engine

// Finding is the engine's output representation of a detected issue. This
// maps 1:1 to the fields the SAST worker persists into findings.findings
// and findings.taint_paths (migration 019, later chunk). Keeping this type
// engine-local and decoupled from the DB schema means the engine has zero
// database dependencies and is trivially unit-testable.
type Finding struct {
	// Identity / classification
	RuleID      string   // e.g. "SC-JAVA-CRYPTO-001"
	Title       string   // short, human-readable
	Description string   // full description from the rule
	Remediation string   // full remediation text from the rule
	CWE         []string // e.g. ["CWE-327", "CWE-328"]
	OWASP       []string // e.g. ["A02:2021"]
	References  []string // from the rule

	// Severity + confidence
	Severity   string  // critical|high|medium|low|info
	Confidence float64 // [0.0, 1.0]

	// Location
	ModulePath string // artifact-relative path
	Function   string // FQN of the enclosing function, empty if at module scope
	Line       int    // 1-indexed
	EndLine    int    // optional
	Column     int    // 1-indexed

	// Fingerprint — stable across cosmetic code changes and across scans.
	// See engine/fingerprint.go for the construction.
	Fingerprint string

	// Evidence chain. For AST-local rules (Chunk SAST-1) this is a single
	// step. For taint-based rules (later chunks) it's the full source→
	// sanitizer-bypass→sink path.
	Evidence []EvidenceStep
}

// EvidenceStep is one hop in a finding's evidence chain.
type EvidenceStep struct {
	StepIndex   int    // 0-indexed
	ModulePath  string // artifact-relative path
	Function    string // enclosing function FQN, empty if at module scope
	Line        int
	EndLine     int
	Opcode      string // the IR opcode at this step
	Description string // human-readable, e.g. "Cipher.getInstance(\"DES\")"
}
