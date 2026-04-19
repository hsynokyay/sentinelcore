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

// ValidSeverities enumerates the severity strings accepted by the engine.
// The list matches findings.findings.severity so rules can be persisted
// without translation.
var validSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

// LoadBuiltins returns the built-in rule set embedded in the binary. These
// are the rules the SAST worker ships with out of the box; signed rule-pack
// overlays land in Chunk SAST-4.
func LoadBuiltins() ([]*Rule, error) {
	return loadFromFS(builtinFS, "builtins")
}

// LoadFromDir loads rules from an on-disk directory. Used by the test
// harness and, eventually, by the signed-pack loader.
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

// Validate performs structural validation on a Rule. This is intentionally
// strict: rules that reach the engine are trusted to be well-formed, so
// every error becomes a load-time failure rather than a runtime surprise.
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
	if r.Language == "" {
		return errors.New("language is required")
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
		if r.Detection.VulnClass == "" {
			return errors.New("taint detection requires vuln_class")
		}
	case "":
		return errors.New("detection.kind is required")
	default:
		return fmt.Errorf("detection.kind %q is not supported", r.Detection.Kind)
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
	Source        AssignPattern
	NameRegexes   []*regexp.Regexp
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
