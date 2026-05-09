// Package rules defines the SentinelCore SAST rule schema and loader.
//
// Rules are JSON documents with stable metadata (CWE, OWASP, severity,
// remediation text) and a detection specification. Schema is versioned —
// `schema_version` defaults to 1 (legacy) when missing. Version 2 adds:
//
//   - top-level taxonomy: category, languages[], tags[]
//   - confidence.modifiers — context-aware bumps for FP reduction
//   - detection.taint — sources / propagators / sanitizers / sinks (the
//     shape every taint-style rule from FAZ 3 onward will use)
//
// Every rule carries enough metadata that a finding emitted by the engine
// can round-trip into the existing findings.findings table without the
// engine knowing anything about the database.
package rules

// Rule is the top-level rule document. All v2 fields are optional so v1
// rules continue to load unchanged; the loader transparently migrates v1
// rules to v2 in memory.
type Rule struct {
	// SchemaVersion defaults to 1 when missing. New rules should set 2.
	SchemaVersion int `json:"schema_version,omitempty"`

	RuleID      string            `json:"rule_id"`
	Name        string            `json:"name"`
	Language    string            `json:"language,omitempty"`  // legacy single-language; prefer Languages
	Languages   []string          `json:"languages,omitempty"` // v2 multi-language support
	Category    string            `json:"category,omitempty"`  // v2 — injection|xss|crypto|secret|...
	Tags        []string          `json:"tags,omitempty"`      // v2 — searchable labels
	CWE         []string          `json:"cwe,omitempty"`
	OWASP       []string          `json:"owasp,omitempty"`
	Severity    string            `json:"severity"` // critical|high|medium|low|info
	Description string            `json:"description"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references,omitempty"`
	Detection   Detection         `json:"detection"`
	Confidence  ConfidenceModel   `json:"confidence"`
	Examples    map[string]string `json:"examples,omitempty"`
}

// Detection describes what the engine should match. Kind discriminates
// which detection sub-structure is consulted.
type Detection struct {
	Kind           DetectionKind   `json:"kind"`
	Patterns       []CallPattern   `json:"patterns,omitempty"`        // ast_call
	AssignPatterns []AssignPattern `json:"assign_patterns,omitempty"` // ast_assign
	VulnClass      string          `json:"vuln_class,omitempty"`      // taint (legacy v1 shape)
	Taint          *TaintSpec      `json:"taint,omitempty"`           // taint (v2 shape — full source/sink/sanitizer model)
}

// DetectionKind is the discriminator for Detection. New kinds are additive
// — adding a kind does not break existing rules.
type DetectionKind string

const (
	DetectionASTCall   DetectionKind = "ast_call"
	DetectionASTAssign DetectionKind = "ast_assign"
	DetectionTaint     DetectionKind = "taint"
)

// ValidCategories is the closed set of rule categories. New categories
// require a code change so dashboards/filters stay coherent.
var ValidCategories = map[string]bool{
	"secret":              true,
	"injection":           true,
	"xss":                 true,
	"path":                true,
	"ssrf":                true,
	"redirect":            true,
	"xxe":                 true,
	"crypto":              true,
	"randomness":          true,
	"auth":                true,
	"authz":               true,
	"session":             true,
	"csrf":                true,
	"deserialization":     true,
	"logging":             true,
	"privacy":             true,
	"error_handling":      true,
	"memory":              true,
	"concurrency":         true,
	"validation":          true,
	"misc":                true,
}

// ValidLanguages is the closed set of supported source languages.
// "javascript" is canonical (the rest of the codebase — parsers, analyzer,
// risk store — already keys on it); "js" is accepted as an alias and
// normalized to "javascript" by MigrateInPlace.
var ValidLanguages = map[string]bool{
	"java":       true,
	"javascript": true,
	"python":     true,
	"csharp":     true,
}

// languageAliases maps non-canonical language names to canonical form.
// Authors can write either; the loader normalizes once at migration time.
var languageAliases = map[string]string{
	"js":         "javascript",
	"ts":         "javascript",
	"typescript": "javascript",
	"py":         "python",
	"cs":         "csharp",
}

// CallPattern matches a Call instruction in the IR. All non-empty fields
// must match; empty fields are wildcards.
//
// ReceiverFQN matches the declared type of the call receiver exactly.
// Callee matches the simple method name.
// If ArgIndex is set and ArgMatchesAny is non-empty, the operand at
// ArgIndex must be a string literal matching at least one of the supplied
// regular expressions.
//
// ArgTextContainsAny / ArgTextMissingAny operate on Instruction.ArgSourceText
// — the verbatim source-text representation of each operand. Use these for
// cookie/JWT options-object patterns where a key's presence (or absence)
// inside an object literal cannot be expressed as a string-literal regex.
//
//   ArgTextContainsAny — pattern fires when the operand source text contains
//   at least one of the listed substrings.
//   ArgTextMissingAny — pattern fires only when NONE of the listed substrings
//   appear in the operand source text. The list represents alternative
//   spellings of the same protective marker (e.g. ["httpOnly", "HttpOnly"]);
//   finding any one form is enough to consider the call safe.
//
// FuncTextContainsAny / FuncTextMissingAny operate on
// Instruction.EnclosingFunctionText — the verbatim source text of the entire
// enclosing function/method body. Use these for patterns that need to assert
// the presence or absence of a sibling statement in the same scope (e.g.
// "addCookie called without setSecure in the same method").
//
//   FuncTextContainsAny — pattern fires when the enclosing function source
//   contains at least one of the listed substrings.
//   FuncTextMissingAny — pattern fires only when NONE of the listed
//   substrings appear in the enclosing function source. List entries are
//   alternative spellings of the same protective marker.
type CallPattern struct {
	ReceiverFQN         string   `json:"receiver_fqn,omitempty"`
	Callee              string   `json:"callee,omitempty"`
	CalleeFQN           string   `json:"callee_fqn,omitempty"`
	ArgIndex            *int     `json:"arg_index,omitempty"`
	ArgMatchesAny       []string `json:"arg_matches_any,omitempty"`
	ArgTextContainsAny  []string `json:"arg_text_contains_any,omitempty"`
	ArgTextMissingAny   []string `json:"arg_text_missing_any,omitempty"`
	FuncTextContainsAny []string `json:"func_text_contains_any,omitempty"`
	FuncTextMissingAny  []string `json:"func_text_missing_any,omitempty"`
	// MessageTemplate is a human-readable description used in the finding
	// title when this pattern fires. Supports the placeholder {{arg}} which
	// expands to the matched string literal (or, for arg_text_* matchers,
	// the operand source text).
	MessageTemplate string `json:"message_template,omitempty"`
}

// AssignPattern matches Store instructions where the variable name and the
// assigned string value both pass heuristic checks. Used for hardcoded-secret
// detection.
type AssignPattern struct {
	// NameMatchesAny: regex list that the variable/field name must match.
	NameMatchesAny []string `json:"name_matches_any"`
	// MinValueLength: minimum string-literal length to consider.
	MinValueLength int `json:"min_value_length,omitempty"`
	// ValuePrefixesAny: if non-empty, the value must start with one of these.
	ValuePrefixesAny []string `json:"value_prefixes_any,omitempty"`
	// ExcludeValues: values matching these patterns are excluded (placeholders).
	ExcludeValues []string `json:"exclude_values,omitempty"`
	// RequireEntropy: if true, reject low-entropy values (e.g. "test", "admin").
	RequireEntropy  bool   `json:"require_entropy,omitempty"`
	MessageTemplate string `json:"message_template,omitempty"`
}

// TaintSpec is the v2 taint detection shape. The engine treats sources as
// "tainted entry points", propagators as "operations that pass taint
// through", sanitizers as "operations that wash taint off", and sinks as
// "dangerous operations that fail when given tainted data".
//
// A finding fires when the engine can prove a data-flow path
// source → (propagators)* → sink with no sanitizer in between.
type TaintSpec struct {
	VulnClass   string         `json:"vuln_class,omitempty"`
	Sources     []TaintNode    `json:"sources"`
	Propagators []TaintNode    `json:"propagators,omitempty"`
	Sanitizers  []TaintNode    `json:"sanitizers,omitempty"`
	Sinks       []TaintNode    `json:"sinks"`
	Evidence    *TaintEvidence `json:"evidence,omitempty"`
}

// TaintNode describes one source/propagator/sanitizer/sink. Kind selects
// which sub-fields are read. Multiple kinds let the same rule express
// "tainted by Spring @RequestParam OR by HttpServletRequest.getParameter
// OR by reading a request cookie".
type TaintNode struct {
	Kind TaintNodeKind `json:"kind"`

	// Kind=api: matches calls/methods by fully-qualified name. ArgumentIndex
	// (when set) restricts the taint check to a specific argument.
	FQN           []string `json:"fqn,omitempty"`
	ArgumentIndex *int     `json:"argument_index,omitempty"`

	// Kind=framework_param: matches function parameters annotated/decorated
	// for a specific framework. Used for "any @RequestParam in a Spring
	// controller is tainted" without listing every method.
	Framework   string   `json:"framework,omitempty"`   // spring_mvc, flask, express, ...
	Annotations []string `json:"annotations,omitempty"` // ["@RequestParam", "@PathVariable"]
	APIs        []string `json:"apis,omitempty"`        // alternative to Annotations for non-annotation frameworks (Flask request.args.get etc.)

	// Kind=type_cast: a cast to one of these types neutralises taint. Used
	// for sanitizers like "(int)id removes SQLi risk for that variable".
	ToTypes []string `json:"to_types,omitempty"`

	// Kind=regex_check: a guard like `if (input.matches("^[A-Za-z0-9]+$"))`
	// upstream of the sink neutralises taint inside the matched branch.
	Pattern string `json:"pattern,omitempty"`

	// Kind=format: string-shaping operations that propagate taint.
	// Operations: ["fstring","format","mod","concat"].
	Operations []string `json:"operations,omitempty"`
}

// TaintNodeKind discriminates TaintNode.
type TaintNodeKind string

const (
	TaintKindAPI            TaintNodeKind = "api"
	TaintKindFrameworkParam TaintNodeKind = "framework_param"
	TaintKindTypeCast       TaintNodeKind = "type_cast"
	TaintKindRegexCheck     TaintNodeKind = "regex_check"
	TaintKindFormat         TaintNodeKind = "format"
)

// TaintEvidence directs how the engine assembles the finding's evidence
// payload. Defaults are sensible — most rules can omit it.
type TaintEvidence struct {
	// Capture controls which fields end up in the finding's evidence_ref.
	// Valid entries: source_line, sink_line, propagation_chain, taint_path_hash.
	Capture []string `json:"capture,omitempty"`
	// MessageTemplate supports {{source.fqn}}, {{sink.fqn}}, {{path_length}}.
	MessageTemplate string `json:"message_template,omitempty"`
}

// ConfidenceModel computes a [0, 1] score per finding from real signals.
// Base is the rule author's prior; Modifiers adjust the score based on
// per-finding context discovered at scan time (e.g. a sanitizer was
// observed, a known-safe constant flowed in, the source was outside
// user-controllable input).
type ConfidenceModel struct {
	Base      float64              `json:"base"`
	Modifiers []ConfidenceModifier `json:"modifiers,omitempty"`
}

// ConfidenceModifier bumps the confidence up or down when a named
// condition is observed. Conditions are interpreted by the engine; unknown
// conditions are ignored (forward-compatible).
//
// Standard conditions:
//
//	sanitizer_present       — at least one sanitizer node fired on the path
//	source_is_user_input    — the matched source is in the user-input class
//	source_is_constant      — the source resolved to a literal constant
//	in_test_path            — the finding was raised under a test directory
//	short_path              — taint travelled fewer than N hops
type ConfidenceModifier struct {
	If    string  `json:"if"`
	Delta float64 `json:"delta"`
}
