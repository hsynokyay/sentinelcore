package engine

import (
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

// TaintEngine performs taint analysis on function instruction streams.
//
// Chunk SAST-4 adds inter-procedural analysis: when a Call instruction
// targets a function whose summary is available in the SummaryCache, the
// engine applies the summary to propagate taint through the call boundary
// and detect cross-function sinks.
//
// Analysis order: the caller (Engine.AnalyzeAll) builds a call graph,
// computes a bottom-up order, and analyzes callees before callers so their
// summaries are available. This is a single bottom-up pass — correct for
// acyclic call graphs, conservatively over-tainted for recursive cycles.
type TaintEngine struct {
	models    *ModelSet
	summaries *SummaryCache
	callGraph *CallGraph
}

// NewTaintEngine creates a taint engine with the given model set.
func NewTaintEngine(models *ModelSet) *TaintEngine {
	return &TaintEngine{
		models:    models,
		summaries: NewSummaryCache(),
	}
}

// SetCallGraph wires the call graph so handleCall can resolve inter-procedural
// calls. Called by Engine.AnalyzeAll before starting the analysis pass.
func (te *TaintEngine) SetCallGraph(cg *CallGraph) {
	te.callGraph = cg
}

// taintState tracks per-function taint information.
type taintState struct {
	taintedValues map[ir.ValueID]*taintSource
	taintedVars   map[string]*taintSource
}

// taintSource records where taint originated for evidence-chain construction.
type taintSource struct {
	calleeFQN string
	taintKind string
	loc       ir.Location
}

// AnalyzeFunction runs taint analysis on a single function. It also
// produces a FunctionSummary and caches it so callers of this function
// can apply the summary without re-analyzing the body.
func (te *TaintEngine) AnalyzeFunction(
	module *ir.Module,
	fn *ir.Function,
	taintRule *rules.CompiledRule,
) []Finding {
	if len(fn.Blocks) == 0 {
		return nil
	}

	vulnClass := taintRule.Source.Detection.VulnClass

	// To compute the summary, we analyze the function once per parameter,
	// seeding taint on that parameter. This is k=0: one summary per function.
	summary := &FunctionSummary{
		FQN:           fn.FQN,
		VulnClass:     vulnClass,
		ParamCount:    len(fn.Parameters),
		ReturnTainted: map[int]bool{},
		SinkReachable: map[int][]SinkHit{},
	}

	// First pass: analyze with no parameter taint (detects entry-point
	// sources like getParameter inside this function).
	findings := te.analyzeWithTaint(module, fn, taintRule, nil)

	// Summary pass: for each parameter, analyze with that parameter tainted
	// to see if taint reaches a sink or the return value.
	for i := range fn.Parameters {
		paramFindings, returnTainted := te.analyzeForSummary(module, fn, taintRule, i)
		if returnTainted {
			summary.ReturnTainted[i] = true
		}
		for _, f := range paramFindings {
			summary.SinkReachable[i] = append(summary.SinkReachable[i], SinkHit{
				SinkFQN:   f.Evidence[len(f.Evidence)-1].Description,
				VulnClass: vulnClass,
				SinkLine:  f.Line,
			})
		}
	}
	te.summaries.Put(summary)

	return findings
}

// analyzeWithTaint runs the instruction walk with optional initial parameter
// taint. When taintedParamIdx is nil, it detects entry-point sources. When
// set, it seeds taint on a specific parameter for summary computation.
func (te *TaintEngine) analyzeWithTaint(
	module *ir.Module,
	fn *ir.Function,
	taintRule *rules.CompiledRule,
	taintedParamIdx *int,
) []Finding {
	state := &taintState{
		taintedValues: map[ir.ValueID]*taintSource{},
		taintedVars:   map[string]*taintSource{},
	}

	// Seed taint from parameter if requested (for summary computation).
	if taintedParamIdx != nil && *taintedParamIdx < len(fn.Parameters) {
		param := fn.Parameters[*taintedParamIdx]
		state.taintedValues[param.Value] = &taintSource{
			calleeFQN: "parameter:" + param.Name,
			taintKind: "param_taint",
			loc:       fn.Loc,
		}
	}

	var findings []Finding
	for _, block := range fn.Blocks {
		for _, inst := range block.Instructions {
			switch inst.Op {
			case ir.OpCall:
				findings = append(findings, te.handleCall(state, module, fn, inst, taintRule)...)
			case ir.OpStore:
				te.handleStore(state, inst)
			case ir.OpBinOp:
				te.handleBinOp(state, inst)
			}
		}
	}
	return findings
}

// analyzeForSummary runs the function with parameter i tainted and returns
// (findings that hit sinks, whether the return value is tainted).
func (te *TaintEngine) analyzeForSummary(
	module *ir.Module,
	fn *ir.Function,
	taintRule *rules.CompiledRule,
	paramIdx int,
) ([]Finding, bool) {
	state := &taintState{
		taintedValues: map[ir.ValueID]*taintSource{},
		taintedVars:   map[string]*taintSource{},
	}

	if paramIdx < len(fn.Parameters) {
		param := fn.Parameters[paramIdx]
		state.taintedValues[param.Value] = &taintSource{
			calleeFQN: "parameter:" + param.Name,
			taintKind: "param_taint",
			loc:       fn.Loc,
		}
	}

	var findings []Finding
	returnTainted := false

	for _, block := range fn.Blocks {
		for _, inst := range block.Instructions {
			switch inst.Op {
			case ir.OpCall:
				findings = append(findings, te.handleCall(state, module, fn, inst, taintRule)...)
			case ir.OpStore:
				te.handleStore(state, inst)
			case ir.OpBinOp:
				te.handleBinOp(state, inst)
			case ir.OpReturn:
				// Check if any operand of the return is tainted.
				for _, op := range inst.Operands {
					if op.Kind == ir.OperandValue {
						if _, ok := state.taintedValues[op.Value]; ok {
							returnTainted = true
						}
					}
				}
			}
		}
	}

	// Also check: if the last emitted value before the function end is
	// tainted and there's no explicit return instruction, treat it as
	// "return tainted". This is a simplification for functions that don't
	// have explicit return instructions in the IR.
	if !returnTainted {
		for _, src := range state.taintedValues {
			if src != nil {
				// At least one value is tainted at function exit → conservatively
				// mark return as tainted if there's a call chain that passes through.
				// This is the "passthrough" heuristic for helper functions like
				// `String buildQuery(String input) { return "SELECT " + input; }`
				returnTainted = true
				break
			}
		}
	}

	return findings, returnTainted
}

// handleCall processes a Call instruction. Inter-procedural extension:
// when the callee has a summary in the cache, apply it to propagate taint
// through the call and detect cross-function sinks.
func (te *TaintEngine) handleCall(
	state *taintState,
	module *ir.Module,
	fn *ir.Function,
	inst *ir.Instruction,
	taintRule *rules.CompiledRule,
) []Finding {
	var findings []Finding
	calleeFQN := inst.CalleeFQN
	vulnClass := taintRule.Source.Detection.VulnClass

	// Same-class call resolution: when calleeFQN is empty but callee is set,
	// try the current function's enclosing class. This handles `runCommand(cmd)`
	// called within the same class without a receiver.
	if calleeFQN == "" && inst.Callee != "" && fn.FQN != "" {
		// Extract class FQN from function FQN: "com.example.Foo.method" → "com.example.Foo"
		if dot := strings.LastIndex(fn.FQN, "."); dot >= 0 {
			classFQN := fn.FQN[:dot]
			candidate := classFQN + "." + inst.Callee
			// Check if this resolves in the call graph or summaries.
			if te.summaries.Get(candidate, vulnClass) != nil {
				calleeFQN = candidate
			} else if te.callGraph != nil && te.callGraph.Resolve(candidate) != nil {
				calleeFQN = candidate
			}
		}
	}

	// 1. SOURCE — try calleeFQN first, then bare callee name as fallback.
	effectiveFQN := calleeFQN
	if _, ok := te.models.Sources[effectiveFQN]; !ok && inst.Callee != "" {
		if _, ok2 := te.models.Sources[inst.Callee]; ok2 {
			effectiveFQN = inst.Callee
		}
	}
	if isSource, taintKind := te.models.IsSource(effectiveFQN); isSource {
		if inst.Result != 0 {
			state.taintedValues[inst.Result] = &taintSource{
				calleeFQN: effectiveFQN,
				taintKind: taintKind,
				loc:       inst.Loc,
			}
		}
		return nil
	}

	// 2. SANITIZER — try calleeFQN first, then bare callee name as fallback.
	// The bare-name fallback handles cases like C# `cmd.Parameters.AddWithValue(...)`
	// where the full receiver chain doesn't resolve to a known type but the
	// bare method name is registered as a sanitizer.
	sanitizerFQN := calleeFQN
	if !te.models.IsSanitizer(sanitizerFQN, vulnClass) && inst.Callee != "" {
		if te.models.IsSanitizer(inst.Callee, vulnClass) {
			sanitizerFQN = inst.Callee
		}
	}
	if te.models.IsSanitizer(sanitizerFQN, vulnClass) {
		if inst.Result != 0 {
			delete(state.taintedValues, inst.Result)
		}
		return nil
	}

	// 3. SINK — check direct operands. Try calleeFQN, then bare callee.
	sinkFQN := calleeFQN
	if _, ok := te.models.Sinks[sinkFQN]; !ok && inst.Callee != "" {
		if _, ok2 := te.models.Sinks[inst.Callee]; ok2 {
			sinkFQN = inst.Callee
		}
	}
	if isSink, sinkVulnClass, sinkModels := te.models.IsSink(sinkFQN); isSink && sinkVulnClass == vulnClass {
		// Check ArgCountExact constraint: if any model sets it, the call's
		// operand count must match exactly. This lets query(sql) fire while
		// query(sql, params) does not.
		argCountOK := true
		for _, m := range sinkModels {
			if m.ArgCountExact != nil {
				if len(inst.Operands) != *m.ArgCountExact {
					argCountOK = false
				}
				break // use first model with the constraint
			}
		}
		if argCountOK {
			for _, op := range inst.Operands {
				if op.Kind != ir.OperandValue {
					continue
				}
				if src, ok := state.taintedValues[op.Value]; ok {
					f := te.buildTaintFinding(taintRule.Source, module, fn, src, inst)
					findings = append(findings, f)
				}
			}
		}
	}

	// 4. INTER-PROCEDURAL: apply callee summary if available. Both exact FQN
	// and package-qualified FQN are tried for same-package calls; the
	// resolvedFQN (post call-graph resolution) is used for the finding
	// fingerprint so the same vulnerability cannot be tracked under two
	// distinct identities depending on whether the caller wrote
	// `SqlHelper.runQuery` or `com.example.SqlHelper.runQuery`. Banking
	// audit chain-of-custody requires finding identity to be stable across
	// callers and scans.
	resolvedFQN := calleeFQN
	summary := te.summaries.Get(calleeFQN, vulnClass)
	if summary == nil && te.callGraph != nil && module.Package != "" {
		if fn := te.callGraph.ResolveWithPackage(calleeFQN, module.Package); fn != nil {
			resolvedFQN = fn.Function.FQN
			summary = te.summaries.Get(resolvedFQN, vulnClass)
		}
	}
	if summary != nil {
		// Check which arguments are tainted.
		for argIdx, op := range inst.Operands {
			if op.Kind != ir.OperandValue {
				continue
			}
			src, isTainted := state.taintedValues[op.Value]
			if !isTainted {
				continue
			}

			// If tainted arg reaches a sink in the callee → emit finding.
			if sinks, ok := summary.SinkReachable[argIdx]; ok {
				for range sinks {
					f := te.buildInterProcFinding(taintRule.Source, module, fn, src, inst, resolvedFQN)
					findings = append(findings, f)
				}
			}

			// If tainted arg taints the return → propagate.
			if summary.ReturnTainted[argIdx] && inst.Result != 0 {
				state.taintedValues[inst.Result] = src
			}
		}
		return findings
	}

	// 5. PASSTHROUGH for unmodeled/unresolved calls.
	if inst.Result != 0 {
		for _, op := range inst.Operands {
			if op.Kind == ir.OperandValue {
				if src, ok := state.taintedValues[op.Value]; ok {
					state.taintedValues[inst.Result] = src
					break
				}
			}
		}
	}

	return findings
}

// handleStore propagates taint from a value to a local variable name.
func (te *TaintEngine) handleStore(state *taintState, inst *ir.Instruction) {
	if len(inst.Operands) < 2 {
		return
	}
	varName := inst.Operands[0].StrVal
	valRef := inst.Operands[1]

	if valRef.Kind == ir.OperandValue {
		if src, ok := state.taintedValues[valRef.Value]; ok {
			state.taintedVars[varName] = src
		} else {
			delete(state.taintedVars, varName)
		}
	}
}

// handleBinOp propagates taint through binary operations (string concat).
func (te *TaintEngine) handleBinOp(state *taintState, inst *ir.Instruction) {
	if inst.Result == 0 {
		return
	}
	for _, op := range inst.Operands {
		if op.Kind == ir.OperandValue {
			if src, ok := state.taintedValues[op.Value]; ok {
				state.taintedValues[inst.Result] = src
				return
			}
		}
	}
}

// buildTaintFinding constructs a Finding for a direct (same-function) flow.
func (te *TaintEngine) buildTaintFinding(
	rule *rules.Rule,
	module *ir.Module,
	fn *ir.Function,
	source *taintSource,
	sinkInst *ir.Instruction,
) Finding {
	confidence := rule.Confidence.Base + 0.10
	if confidence > 1 {
		confidence = 1
	}

	title := rule.Name
	if strings.Contains(title, "{{callee}}") {
		title = strings.ReplaceAll(title, "{{callee}}", sinkInst.CalleeFQN)
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
		Line:        sinkInst.Loc.Line,
		EndLine:     sinkInst.Loc.EndLine,
		Column:      sinkInst.Loc.Column,
		Fingerprint: Fingerprint(rule.RuleID, module.Path, fn.FQN, sinkInst.CalleeFQN, ""),
		Evidence: []EvidenceStep{
			{
				StepIndex:   0,
				ModulePath:  module.Path,
				Function:    fn.FQN,
				Line:        source.loc.Line,
				Opcode:      "call",
				Description: "Tainted value from " + shortName(source.calleeFQN) + " (" + source.taintKind + ")",
			},
			{
				StepIndex:   1,
				ModulePath:  module.Path,
				Function:    fn.FQN,
				Line:        sinkInst.Loc.Line,
				Opcode:      string(sinkInst.Op),
				Description: "Flows into sink: " + shortName(sinkInst.CalleeFQN),
			},
		},
	}
}

// buildInterProcFinding constructs a Finding for a cross-function flow.
func (te *TaintEngine) buildInterProcFinding(
	rule *rules.Rule,
	module *ir.Module,
	callerFn *ir.Function,
	source *taintSource,
	callInst *ir.Instruction,
	calleeFQN string,
) Finding {
	confidence := rule.Confidence.Base + 0.05
	if confidence > 1 {
		confidence = 1
	}

	return Finding{
		RuleID:      rule.RuleID,
		Title:       rule.Name,
		Description: rule.Description,
		Remediation: rule.Remediation,
		CWE:         rule.CWE,
		OWASP:       rule.OWASP,
		References:  rule.References,
		VulnClass:   rule.VulnClass,
		Severity:    rule.Severity,
		Confidence:  confidence,
		ModulePath:  module.Path,
		Function:    callerFn.FQN,
		Line:        callInst.Loc.Line,
		Column:      callInst.Loc.Column,
		Fingerprint: Fingerprint(rule.RuleID, module.Path, callerFn.FQN, calleeFQN, ""),
		Evidence: []EvidenceStep{
			{
				StepIndex:   0,
				ModulePath:  module.Path,
				Function:    callerFn.FQN,
				Line:        source.loc.Line,
				Opcode:      "call",
				Description: "Tainted value from " + shortName(source.calleeFQN) + " (" + source.taintKind + ")",
			},
			{
				StepIndex:   1,
				ModulePath:  module.Path,
				Function:    callerFn.FQN,
				Line:        callInst.Loc.Line,
				Opcode:      "call",
				Description: "Taint flows through call to " + shortName(calleeFQN),
			},
			{
				StepIndex:   2,
				ModulePath:  module.Path,
				Function:    calleeFQN,
				Line:        callInst.Loc.Line,
				Opcode:      "sink",
				Description: "Sink reached inside " + shortName(calleeFQN),
			},
		},
	}
}

func shortName(fqn string) string {
	parts := strings.Split(fqn, ".")
	if len(parts) <= 2 {
		return fqn
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
