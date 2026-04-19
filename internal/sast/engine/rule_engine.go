package engine

import (
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

// matchASTCallRule walks every Call instruction in the module and emits a
// Finding for each match against any pattern in the rule. This is the
// AST-local (non-taint) matching path; Chunk SAST-3 adds the taint-based
// matcher alongside this one.
//
// A pattern matches iff:
//
//  1. The instruction's Op is OpCall.
//  2. The instruction's ReceiverType equals pattern.ReceiverFQN, if set.
//  3. The instruction's Callee equals pattern.Callee, if set.
//  4. The instruction's CalleeFQN equals pattern.CalleeFQN, if set.
//  5. If pattern.ArgIndex is set, the operand at that index must be a
//     constant string literal matching at least one of the compiled regexes.
//
// Rules are authored so that most patterns pin only receiver + callee +
// arg_index + arg_matches_any. The four-way AND matches Fortify's
// "structural rule" mode.
func matchASTCallRule(module *ir.Module, rule *rules.CompiledRule) []Finding {
	var out []Finding
	for _, class := range module.Classes {
		for _, fn := range class.Methods {
			for _, block := range fn.Blocks {
				for _, inst := range block.Instructions {
					if inst.Op != ir.OpCall {
						continue
					}
					for _, p := range rule.Patterns {
						if !callMatchesPattern(inst, p) {
							continue
						}
						matchedArg := extractMatchedArg(inst, p)
						f := buildFinding(rule.Source, module, fn, inst, matchedArg, p)
						out = append(out, f)
						// A single instruction can match multiple patterns in
						// the same rule; we continue rather than break so every
						// pattern gets a chance.
					}
				}
			}
		}
	}
	return out
}

// callMatchesPattern performs the structural match (1-5 above). It does not
// do any regex work if any earlier check fails, so matching is cheap.
func callMatchesPattern(inst *ir.Instruction, p rules.CompiledPattern) bool {
	src := p.Source
	if src.ReceiverFQN != "" && inst.ReceiverType != src.ReceiverFQN {
		return false
	}
	if src.Callee != "" && inst.Callee != src.Callee {
		return false
	}
	if src.CalleeFQN != "" && inst.CalleeFQN != src.CalleeFQN {
		return false
	}
	if src.ArgIndex != nil && len(p.ArgRegexes) > 0 {
		idx := *src.ArgIndex
		if idx < 0 || idx >= len(inst.Operands) {
			return false
		}
		op := inst.Operands[idx]
		if op.Kind != ir.OperandConstString {
			// We only match string literals. A value that came from a
			// parameter or a field access is a "don't know" — the rule
			// engine's AST-local path skips it; the taint engine (later
			// chunk) can reach back to the definition.
			return false
		}
		matched := false
		for _, re := range p.ArgRegexes {
			if re.MatchString(op.StrVal) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// extractMatchedArg returns the matched string-literal argument if the
// pattern pinned one, or "" otherwise. Used for fingerprint key and
// evidence description.
func extractMatchedArg(inst *ir.Instruction, p rules.CompiledPattern) string {
	if p.Source.ArgIndex == nil {
		return ""
	}
	idx := *p.Source.ArgIndex
	if idx < 0 || idx >= len(inst.Operands) {
		return ""
	}
	op := inst.Operands[idx]
	if op.Kind != ir.OperandConstString {
		return ""
	}
	return op.StrVal
}

// buildFinding assembles the public Finding record from the rule, the
// matched instruction, and the matched argument.
func buildFinding(rule *rules.Rule, module *ir.Module, fn *ir.Function, inst *ir.Instruction, matchedArg string, p rules.CompiledPattern) Finding {
	title := rule.Name
	if p.Source.MessageTemplate != "" {
		title = strings.ReplaceAll(p.Source.MessageTemplate, "{{arg}}", matchedArg)
	}

	confidence := rule.Confidence.Base
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	f := Finding{
		RuleID:      rule.RuleID,
		Title:       title,
		Description: rule.Description,
		Remediation: rule.Remediation,
		CWE:         rule.CWE,
		OWASP:       rule.OWASP,
		References:  rule.References,
		Severity:    rule.Severity,
		Confidence:  confidence,
		ModulePath:  module.Path,
		Function:    fn.FQN,
		Line:        inst.Loc.Line,
		EndLine:     inst.Loc.EndLine,
		Column:      inst.Loc.Column,
		Fingerprint: Fingerprint(rule.RuleID, module.Path, fn.FQN, inst.CalleeFQN, matchedArg),
		Evidence: []EvidenceStep{
			{
				StepIndex:   0,
				ModulePath:  module.Path,
				Function:    fn.FQN,
				Line:        inst.Loc.Line,
				EndLine:     inst.Loc.EndLine,
				Opcode:      string(inst.Op),
				Description: describeCall(inst, matchedArg),
			},
		},
	}
	return f
}

// describeCall renders a short, human-readable description of a Call
// instruction for evidence display. This is what the UI's Analysis Trace
// block shows for each step.
func describeCall(inst *ir.Instruction, matchedArg string) string {
	var sb strings.Builder
	if inst.ReceiverType != "" {
		// Use the short name for readability: "Cipher.getInstance(...)".
		receiver := inst.ReceiverType
		if dot := strings.LastIndex(receiver, "."); dot >= 0 {
			receiver = receiver[dot+1:]
		}
		sb.WriteString(receiver)
		sb.WriteString(".")
	}
	sb.WriteString(inst.Callee)
	sb.WriteString("(")
	if matchedArg != "" {
		sb.WriteString(`"`)
		sb.WriteString(matchedArg)
		sb.WriteString(`"`)
	} else {
		sb.WriteString("…")
	}
	sb.WriteString(")")
	return sb.String()
}
