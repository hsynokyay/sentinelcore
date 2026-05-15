package engine

import (
	"math"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

// matchASTAssignRule walks every Store instruction in the module and emits a
// Finding when the variable name and string-literal value match any
// AssignPattern in the rule. Used for hardcoded-secret detection.
func matchASTAssignRule(module *ir.Module, rule *rules.CompiledRule) []Finding {
	var out []Finding
	for _, cls := range module.Classes {
		for _, fn := range cls.Methods {
			for _, block := range fn.Blocks {
				for _, inst := range block.Instructions {
					if inst.Op != ir.OpStore {
						continue
					}
					if len(inst.Operands) < 2 {
						continue
					}
					// Operands[0] = const_string varName
					// Operands[1] = const_string value (for field inits) or value ref
					nameOp := inst.Operands[0]
					valOp := inst.Operands[1]
					if nameOp.Kind != ir.OperandConstString {
						continue
					}
					// We only match string-literal assignments.
					if valOp.Kind != ir.OperandConstString {
						continue
					}

					varName := nameOp.StrVal
					strValue := valOp.StrVal

					for _, ap := range rule.AssignPatterns {
						if matchesAssignPattern(varName, strValue, ap) {
							f := buildSecretFinding(rule.Source, module, fn, inst, varName, strValue, ap)
							out = append(out, f)
							break // one finding per instruction
						}
					}
				}
			}
		}
	}
	return out
}

// matchesAssignPattern checks whether a (varName, strValue) pair matches the
// compiled assign pattern.
func matchesAssignPattern(varName, strValue string, ap rules.CompiledAssignPattern) bool {
	// 1. Name must match at least one regex (case-insensitive via the regex itself).
	nameMatch := false
	for _, re := range ap.NameRegexes {
		if re.MatchString(varName) {
			nameMatch = true
			break
		}
	}
	if !nameMatch {
		return false
	}

	// 2. Value must be long enough.
	minLen := ap.Source.MinValueLength
	if minLen <= 0 {
		minLen = 6 // sensible default — skip trivially short values
	}
	if len(strValue) < minLen {
		return false
	}

	// 3. Value must not match any exclude pattern (placeholder values).
	for _, re := range ap.ExcludeRegexes {
		if re.MatchString(strValue) {
			return false
		}
	}

	// 4. If prefix list is set, value must start with one.
	if len(ap.Source.ValuePrefixesAny) > 0 {
		prefixMatch := false
		for _, pfx := range ap.Source.ValuePrefixesAny {
			if strings.HasPrefix(strValue, pfx) {
				prefixMatch = true
				break
			}
		}
		if !prefixMatch {
			// Fall through to entropy check — if the value has high entropy,
			// still flag it even without a known prefix.
			if ap.Source.RequireEntropy && !isHighEntropy(strValue) {
				return false
			}
			// If no prefix match and no entropy requirement, reject.
			if !ap.Source.RequireEntropy {
				return false
			}
		}
	} else if ap.Source.RequireEntropy && !isHighEntropy(strValue) {
		return false
	}

	return true
}

// isHighEntropy returns true if the string has Shannon entropy above a
// practical threshold for credential detection. The threshold is tuned to
// catch real tokens (typically 3.5+ bits/char) while rejecting English words
// and simple patterns like "password123" (typically <3.0 bits/char).
func isHighEntropy(s string) bool {
	if len(s) < 8 {
		return false
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy >= 3.5
}

// buildSecretFinding constructs a Finding for a hardcoded secret. The
// evidence intentionally redacts the secret value — it shows the first 4
// characters and the length, never the full string.
func buildSecretFinding(
	rule *rules.Rule,
	module *ir.Module,
	fn *ir.Function,
	inst *ir.Instruction,
	varName, strValue string,
	ap rules.CompiledAssignPattern,
) Finding {
	title := rule.Name
	if ap.Source.MessageTemplate != "" {
		title = strings.ReplaceAll(ap.Source.MessageTemplate, "{{name}}", varName)
	}

	// Redact the value for the evidence description.
	redacted := redactSecret(strValue)

	confidence := rule.Confidence.Base
	// Boost for known prefixes.
	for _, pfx := range ap.Source.ValuePrefixesAny {
		if strings.HasPrefix(strValue, pfx) {
			confidence += 0.10
			break
		}
	}
	// Boost for high entropy.
	if isHighEntropy(strValue) {
		confidence += 0.05
	}
	if confidence > 1 {
		confidence = 1
	}

	return Finding{
		RuleID:      rule.RuleID,
		Title:       title,
		Description: rule.Description,
		Remediation: rule.Remediation,
		CWE:         rule.CWE,
		OWASP:       rule.OWASP,
		References:  rule.References,
		VulnClass:   rule.VulnClass,
		Severity:    rule.Severity,
		Confidence:  confidence,
		ModulePath:  module.Path,
		Function:    fn.FQN,
		Line:        inst.Loc.Line,
		Column:      inst.Loc.Column,
		Fingerprint: Fingerprint(rule.RuleID, module.Path, fn.FQN, varName, ""),
		Evidence: []EvidenceStep{
			{
				StepIndex:   0,
				ModulePath:  module.Path,
				Function:    fn.FQN,
				Line:        inst.Loc.Line,
				Opcode:      "store",
				Description: varName + " = " + redacted,
			},
		},
	}
}

// redactSecret shows the first 4 characters and the length, never the full
// value. "ghp_abcdefghijklmnop" → "ghp_… (20 chars)".
func redactSecret(s string) string {
	if len(s) <= 4 {
		return "\"****\""
	}
	prefix := s[:4]
	return "\"" + prefix + "…\" (" + strings.Repeat("", 0) + itoa(len(s)) + " chars)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
