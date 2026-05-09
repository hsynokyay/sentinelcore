package rules

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed builtins/*.json
var builtinFS embed.FS

// validSeverities enumerates the severity strings accepted by the engine.
// The list matches findings.findings.severity so rules can be persisted
// without translation.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

// CurrentSchemaVersion is the schema version new rules should declare.
// Older rules without schema_version are accepted and migrated to v2 in
// memory at load time.
const CurrentSchemaVersion = 2

// LoadBuiltins returns the built-in rule set embedded in the binary. v1
// rules are auto-migrated to v2 before validation so callers always see
// the current shape.
func LoadBuiltins() ([]*Rule, error) {
	return loadFromFS(builtinFS, "builtins")
}

// LoadFromDir loads rules from an on-disk directory. Used by the test
// harness, the validator CLI, and the signed-pack loader (future).
func LoadFromDir(dir string) ([]*Rule, error) {
	return loadFromFS(os.DirFS(dir), ".")
}

func loadFromFS(fsys fs.FS, root string) ([]*Rule, error) {
	var rules []*Rule
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, rErr := fs.ReadFile(fsys, path)
		if rErr != nil {
			return fmt.Errorf("read %s: %w", path, rErr)
		}
		var rule Rule
		if jErr := json.Unmarshal(data, &rule); jErr != nil {
			return fmt.Errorf("parse %s: %w", path, jErr)
		}
		MigrateInPlace(&rule)
		if vErr := Validate(&rule); vErr != nil {
			return fmt.Errorf("validate %s: %w", path, vErr)
		}
		rules = append(rules, &rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// MigrateInPlace promotes a v1 rule (no schema_version, single Language,
// no category) to the v2 in-memory shape. It's idempotent — running it on
// a v2 rule is a no-op.
//
// Concretely:
//   - SchemaVersion: 0 → 2
//   - Languages: [] → [Language] when Language is set
//   - Category: "" → inferred from rule_id token (SC-LANG-CAT-NN)
//   - Detection.Taint: nil with VulnClass set → minimal TaintSpec wrapper
//     so engine code that prefers .Taint over .VulnClass keeps working
//
// Inferred categories use the rule_id naming convention; unknown tokens
// fall back to "misc" rather than failing — operators can fix the rule
// later without breaking the load.
func MigrateInPlace(r *Rule) {
	if r.SchemaVersion == 0 {
		r.SchemaVersion = CurrentSchemaVersion
	}
	// Normalize legacy single-language to canonical alias.
	if r.Language != "" {
		if canonical, ok := languageAliases[r.Language]; ok {
			r.Language = canonical
		}
	}
	if len(r.Languages) == 0 && r.Language != "" {
		r.Languages = []string{r.Language}
	}
	// Normalize each entry in v2 Languages too.
	for i, lang := range r.Languages {
		if canonical, ok := languageAliases[lang]; ok {
			r.Languages[i] = canonical
		}
	}
	if r.Category == "" {
		r.Category = inferCategoryFromRuleID(r.RuleID)
	}
	// We deliberately do NOT synthesize a TaintSpec wrapper for v1 rules
	// that only carry vuln_class — the engine still reads the v1 field, and
	// promoting to an empty TaintSpec would just trip the v2 validator
	// (which insists sources/sinks are populated). Authors who want the v2
	// shape opt in by setting detection.taint themselves.
}

// categoryByToken maps the third path-segment of a rule_id (SC-<LANG>-<TOKEN>-NN)
// to the canonical Category enum. Multiple tokens can map to the same
// category — that's by design (HARDCODED-SECRET, SECRET, CREDS all map
// to "secret").
var categoryByToken = map[string]string{
	"SQL":      "injection",
	"SQLI":     "injection",
	"CMD":      "injection",
	"LDAP":     "injection",
	"XPATH":    "injection",
	"NOSQL":    "injection",
	"SSTI":     "injection",
	"EL":       "injection",
	"INJ":      "injection",
	"EVAL":     "injection",
	"PROTO":    "injection",
	"XSS":      "xss",
	"PATH":     "path",
	"FILE":     "path",
	"ZIPSLIP":  "path",
	"SSRF":     "ssrf",
	"REDIRECT": "redirect",
	"OPENREDIR": "redirect",
	"XXE":      "xxe",
	"XML":      "xxe",
	"CRYPTO":   "crypto",
	"HASH":     "crypto",
	"CIPHER":   "crypto",
	"TLS":      "crypto",
	"RAND":     "randomness",
	"AUTH":     "auth",
	"AUTHZ":    "authz",
	"JWT":      "auth",
	"SESSION":  "session",
	"COOKIE":   "session",
	"CSRF":     "csrf",
	"DESER":    "deserialization",
	"SERIAL":   "deserialization",
	"PICKLE":   "deserialization",
	"YAML":     "deserialization",
	"LOG":      "logging",
	"PII":      "privacy",
	"PRIV":     "privacy",
	"ERR":      "error_handling",
	"MEM":      "memory",
	"BUF":      "memory",
	"NULL":     "memory",
	"RACE":     "concurrency",
	"TOCTOU":   "concurrency",
	"CONC":     "concurrency",
	"VAL":      "validation",
	"SECRET":   "secret",
	"CREDS":    "secret",
	"KEY":      "secret",
}

func inferCategoryFromRuleID(ruleID string) string {
	parts := strings.Split(ruleID, "-")
	if len(parts) < 3 {
		return "misc"
	}
	// rule_id shape: SC-<LANG>-<TOKEN>[-<MORE>...]-<NN>. Probe each segment
	// from index 2 onward — earlier segments win for legacy rules like
	// SC-JAVA-DESER-001 (token "DESER" at index 2) and modern compound rules
	// like SC-PY-DESER-PICKLE-001 (still wins at index 2).
	for i := 2; i < len(parts)-1; i++ {
		if cat, ok := categoryByToken[strings.ToUpper(parts[i])]; ok {
			return cat
		}
	}
	return "misc"
}

// Validate performs structural validation on a Rule. This is intentionally
// strict: rules that reach the engine are trusted to be well-formed, so
// every error becomes a load-time failure rather than a runtime surprise.
//
// v2 fields are checked when present. v1-only rules continue to validate
// because every v2 field has a sensible default applied by MigrateInPlace.
func Validate(r *Rule) error {
	if r.RuleID == "" {
		return errors.New("rule_id is required")
	}
	if !strings.HasPrefix(r.RuleID, "SC-") {
		return fmt.Errorf("rule_id %q must start with SC-", r.RuleID)
	}
	if r.Name == "" {
		return errors.New("name is required")
	}

	// Languages (v2) must be non-empty and from the closed set. Migration
	// already promoted Language→Languages, so we only check the v2 field.
	if len(r.Languages) == 0 {
		return errors.New("languages is required (or set legacy 'language' field)")
	}
	for _, lang := range r.Languages {
		if !ValidLanguages[lang] {
			return fmt.Errorf("language %q is not one of java|js|python|csharp", lang)
		}
	}

	if r.Category != "" && !ValidCategories[r.Category] {
		return fmt.Errorf("category %q is not in the closed set (see ValidCategories)", r.Category)
	}

	if !validSeverities[r.Severity] {
		return fmt.Errorf("severity %q is not one of critical|high|medium|low|info", r.Severity)
	}
	if r.Description == "" {
		return errors.New("description is required")
	}
	if r.Remediation == "" {
		return errors.New("remediation is required")
	}
	if r.Confidence.Base < 0 || r.Confidence.Base > 1 {
		return fmt.Errorf("confidence.base must be in [0, 1], got %v", r.Confidence.Base)
	}
	for i, m := range r.Confidence.Modifiers {
		if m.If == "" {
			return fmt.Errorf("confidence.modifiers[%d]: 'if' is required", i)
		}
		if m.Delta < -1 || m.Delta > 1 {
			return fmt.Errorf("confidence.modifiers[%d]: delta must be in [-1, 1], got %v", i, m.Delta)
		}
	}

	switch r.Detection.Kind {
	case DetectionASTCall:
		if len(r.Detection.Patterns) == 0 {
			return errors.New("ast_call detection requires at least one pattern")
		}
		for i, p := range r.Detection.Patterns {
			if p.ReceiverFQN == "" && p.Callee == "" && p.CalleeFQN == "" {
				return fmt.Errorf("pattern %d must specify at least one of receiver_fqn, callee, callee_fqn", i)
			}
			for _, expr := range p.ArgMatchesAny {
				if _, rErr := regexp.Compile(expr); rErr != nil {
					return fmt.Errorf("pattern %d arg_matches_any regex %q: %w", i, expr, rErr)
				}
			}
		}
	case DetectionASTAssign:
		if len(r.Detection.AssignPatterns) == 0 {
			return errors.New("ast_assign detection requires at least one assign_pattern")
		}
		for i, ap := range r.Detection.AssignPatterns {
			if len(ap.NameMatchesAny) == 0 {
				return fmt.Errorf("assign_pattern %d: name_matches_any is required", i)
			}
			for _, expr := range ap.NameMatchesAny {
				if _, rErr := regexp.Compile(expr); rErr != nil {
					return fmt.Errorf("assign_pattern %d name regex %q: %w", i, expr, rErr)
				}
			}
			for _, expr := range ap.ExcludeValues {
				if _, rErr := regexp.Compile(expr); rErr != nil {
					return fmt.Errorf("assign_pattern %d exclude regex %q: %w", i, expr, rErr)
				}
			}
		}
	case DetectionTaint:
		// Either v1 (vuln_class) or v2 (taint{...}) form is acceptable; v2 is
		// preferred and richer.
		if r.Detection.Taint == nil && r.Detection.VulnClass == "" {
			return errors.New("taint detection requires either taint{...} (v2) or vuln_class (v1)")
		}
		if r.Detection.Taint != nil {
			if err := validateTaint(r.Detection.Taint); err != nil {
				return err
			}
		}
	case "":
		return errors.New("detection.kind is required")
	default:
		return fmt.Errorf("detection.kind %q is not supported", r.Detection.Kind)
	}
	return nil
}

func validateTaint(t *TaintSpec) error {
	if len(t.Sources) == 0 {
		return errors.New("taint.sources is required (must have at least one source)")
	}
	if len(t.Sinks) == 0 {
		return errors.New("taint.sinks is required (must have at least one sink)")
	}
	check := func(group string, nodes []TaintNode) error {
		for i, n := range nodes {
			if err := validateTaintNode(n); err != nil {
				return fmt.Errorf("taint.%s[%d]: %w", group, i, err)
			}
		}
		return nil
	}
	if err := check("sources", t.Sources); err != nil {
		return err
	}
	if err := check("propagators", t.Propagators); err != nil {
		return err
	}
	if err := check("sanitizers", t.Sanitizers); err != nil {
		return err
	}
	if err := check("sinks", t.Sinks); err != nil {
		return err
	}
	return nil
}

func validateTaintNode(n TaintNode) error {
	switch n.Kind {
	case TaintKindAPI:
		if len(n.FQN) == 0 {
			return errors.New("api kind requires fqn")
		}
	case TaintKindFrameworkParam:
		if n.Framework == "" {
			return errors.New("framework_param kind requires framework")
		}
		if len(n.Annotations) == 0 && len(n.APIs) == 0 {
			return errors.New("framework_param kind requires either annotations or apis")
		}
	case TaintKindTypeCast:
		if len(n.ToTypes) == 0 {
			return errors.New("type_cast kind requires to_types")
		}
	case TaintKindRegexCheck:
		if n.Pattern == "" {
			return errors.New("regex_check kind requires pattern")
		}
		if _, err := regexp.Compile(n.Pattern); err != nil {
			return fmt.Errorf("regex_check pattern: %w", err)
		}
	case TaintKindFormat:
		if len(n.Operations) == 0 {
			return errors.New("format kind requires operations")
		}
	case "":
		return errors.New("kind is required")
	default:
		return fmt.Errorf("kind %q is not supported", n.Kind)
	}
	return nil
}

// CompiledPattern is a CallPattern with its regex list pre-compiled. The
// rule engine uses CompiledRule for matching so each scan pays the regex
// compile cost exactly once at startup.
type CompiledPattern struct {
	Source     CallPattern
	ArgRegexes []*regexp.Regexp
}

// CompiledAssignPattern is an AssignPattern with its regex lists pre-compiled.
type CompiledAssignPattern struct {
	Source         AssignPattern
	NameRegexes    []*regexp.Regexp
	ExcludeRegexes []*regexp.Regexp
}

// CompiledRule is a Rule with every regex pre-compiled.
type CompiledRule struct {
	Source         *Rule
	Patterns       []CompiledPattern
	AssignPatterns []CompiledAssignPattern
}

// Compile pre-compiles every regex in a rule. Compile is safe to call only
// on rules that have already passed Validate.
func Compile(r *Rule) (*CompiledRule, error) {
	cr := &CompiledRule{Source: r}
	for _, p := range r.Detection.Patterns {
		cp := CompiledPattern{Source: p}
		for _, expr := range p.ArgMatchesAny {
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, err
			}
			cp.ArgRegexes = append(cp.ArgRegexes, re)
		}
		cr.Patterns = append(cr.Patterns, cp)
	}
	for _, ap := range r.Detection.AssignPatterns {
		cap := CompiledAssignPattern{Source: ap}
		for _, expr := range ap.NameMatchesAny {
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, err
			}
			cap.NameRegexes = append(cap.NameRegexes, re)
		}
		for _, expr := range ap.ExcludeValues {
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, err
			}
			cap.ExcludeRegexes = append(cap.ExcludeRegexes, re)
		}
		cr.AssignPatterns = append(cr.AssignPatterns, cap)
	}
	return cr, nil
}

// CompileAll compiles every rule in a slice.
func CompileAll(rs []*Rule) ([]*CompiledRule, error) {
	out := make([]*CompiledRule, 0, len(rs))
	for _, r := range rs {
		cr, err := Compile(r)
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", r.RuleID, err)
		}
		out = append(out, cr)
	}
	return out, nil
}

// RulesDir is a helper that resolves an on-disk rules directory relative to
// the caller. Used by tests.
func RulesDir(parts ...string) string {
	return filepath.Join(parts...)
}
