// Package bench runs the SentinelCore SAST engine against a labeled benchmark
// corpus and produces a per-class precision/recall scorecard. This is the
// calibration loop described in the SAST architecture document — the engine
// improves by benchmarking against known-labeled cases, not by guessing.
//
// Usage:
//
//	go test -v ./internal/sast/bench/ -run TestBenchmark
//
// Or via the runner directly:
//
//	results := bench.Run(corpusDir, manifestPath)
//	bench.PrintScorecard(results)
package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/engine"
	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/csharp"
	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/java"
	jsfrontend "github.com/sentinelcore/sentinelcore/internal/sast/frontend/js"
	"github.com/sentinelcore/sentinelcore/internal/sast/frontend/python"
	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/vulnclass"
)

// scorecardOrderStrings adapts vulnclass.ScorecardOrder() into the
// string slice the markdown / stdout formatters consume. Centralized
// here so future additions to the registry's scorecard subset land in
// both PrintScorecard and ScorecardMarkdown without duplication.
func scorecardOrderStrings() []string {
	vcs := vulnclass.ScorecardOrder()
	out := make([]string, len(vcs))
	for i, vc := range vcs {
		out[i] = string(vc)
	}
	return out
}

// Manifest is the benchmark corpus descriptor.
type Manifest struct {
	Version     string `json:"version"`
	Description string `json:"description"`
	Cases       []Case `json:"cases"`
}

// Case is a single benchmark test case.
//
// Manifest schema accepts EITHER:
//   - "rule":  "SC-X-Y-NNN"            — single expected rule (legacy)
//   - "rules": ["SC-X-Y-NNN", ...]     — any-of list (Sprint 1.2-fix)
//
// The two forms are mutually exclusive per entry. Match semantics is
// "any rule fires → expected satisfied", which models the post-Sprint-1.2
// reality that a single vuln location may be reported by either a generic
// or a specialized rule depending on which one wins dedup tie-break. The
// manifest does not (and should not) pin which specific rule_id wins —
// that is an implementation detail of the dedup pass.
//
// After unmarshal both forms are normalized into Rules so downstream
// code only deals with the slice form.
type Case struct {
	ID     string   `json:"id"`
	File   string   `json:"file"`   // relative to corpus root
	Class  string   `json:"class"`  // vulnerability class
	Expect string   `json:"expect"` // "positive" or "negative"
	Rules  []string `json:"-"`      // populated by UnmarshalJSON; never serialized back
}

// caseRaw mirrors the on-disk JSON shape so we can validate the rule/rules
// pair without writing field-by-field copies in UnmarshalJSON.
type caseRaw struct {
	ID     string   `json:"id"`
	File   string   `json:"file"`
	Class  string   `json:"class"`
	Expect string   `json:"expect"`
	Rule   *string  `json:"rule,omitempty"`
	Rules  []string `json:"rules,omitempty"`
}

// UnmarshalJSON enforces the rule/rules contract and normalizes both
// forms into Case.Rules. Errors are wrapped with the case ID (when
// available) so manifest authoring mistakes are localizable.
func (c *Case) UnmarshalJSON(data []byte) error {
	var raw caseRaw
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	hasRule := raw.Rule != nil
	hasRules := raw.Rules != nil // a present-but-empty array still counts as "supplied"

	switch {
	case hasRule && hasRules:
		return fmt.Errorf("case %q: fields \"rule\" and \"rules\" are mutually exclusive — pick one", raw.ID)
	case hasRules && len(raw.Rules) == 0:
		return fmt.Errorf("case %q: \"rules\" must be a non-empty array", raw.ID)
	case !hasRule && !hasRules:
		return fmt.Errorf("case %q: must specify either \"rule\" (string) or \"rules\" (array)", raw.ID)
	}

	c.ID = raw.ID
	c.File = raw.File
	c.Class = raw.Class
	c.Expect = raw.Expect
	if hasRule {
		c.Rules = []string{*raw.Rule}
	} else {
		c.Rules = raw.Rules
	}
	return nil
}

// CaseResult is the outcome of running one benchmark case.
type CaseResult struct {
	Case     Case
	Findings []engine.Finding
	// TP: expect=positive AND at least one finding with the expected rule fired.
	// FP: expect=negative AND at least one finding with the expected rule fired.
	// FN: expect=positive AND no finding with the expected rule fired.
	// TN: expect=negative AND no finding with the expected rule fired.
	Outcome string // "TP", "FP", "FN", "TN"
}

// ClassScore holds per-class metrics.
type ClassScore struct {
	Class     string
	Total     int
	Positives int
	Negatives int
	TP        int
	FP        int
	FN        int
	TN        int
	Precision float64
	Recall    float64
	F1        float64
}

// BenchmarkResult is the complete benchmark output.
type BenchmarkResult struct {
	Cases    []CaseResult
	ByClass  map[string]*ClassScore
	Overall  ClassScore
}

// Run executes the benchmark: loads manifest, parses each file, runs the
// engine, and classifies each case outcome.
func Run(corpusDir, manifestPath string) (*BenchmarkResult, error) {
	// Load manifest
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	// Initialize engine
	eng, err := engine.NewFromBuiltins()
	if err != nil {
		return nil, fmt.Errorf("engine init: %w", err)
	}

	result := &BenchmarkResult{
		ByClass: map[string]*ClassScore{},
	}

	for _, c := range manifest.Cases {
		absPath := filepath.Join(corpusDir, c.File)
		relPath := c.File

		// Parse — dispatch by file extension.
		var mod *ir.Module
		var parseErr error
		ext := strings.ToLower(filepath.Ext(c.File))
		switch ext {
		case ".js", ".ts", ".jsx", ".tsx":
			mod, parseErr = jsfrontend.ParseFile(absPath, relPath)
		case ".py":
			mod, parseErr = python.ParseFile(absPath, relPath)
		case ".cs":
			mod, parseErr = csharp.ParseFile(absPath, relPath)
		default:
			mod, parseErr = java.ParseFile(absPath, relPath)
		}
		if parseErr != nil {
			result.Cases = append(result.Cases, CaseResult{
				Case:    c,
				Outcome: outcomeFor(c.Expect, false),
			})
			continue
		}

		// Analyze
		findings := eng.AnalyzeAll([]*ir.Module{mod})

		// Check whether ANY of the case's expected rules fired. A
		// manifest entry passes once any one rule_id from c.Rules is
		// present in the engine output — see the Case doc comment for
		// rationale (dedup tie-break is an implementation detail; the
		// manifest pins which vuln must be caught, not which rule wins).
		expected := make(map[string]struct{}, len(c.Rules))
		for _, r := range c.Rules {
			expected[r] = struct{}{}
		}
		matched := false
		var relevantFindings []engine.Finding
		for _, f := range findings {
			if _, ok := expected[f.RuleID]; ok {
				matched = true
				relevantFindings = append(relevantFindings, f)
			}
		}

		outcome := outcomeFor(c.Expect, matched)
		result.Cases = append(result.Cases, CaseResult{
			Case:     c,
			Findings: relevantFindings,
			Outcome:  outcome,
		})

		// Accumulate per-class
		cs, ok := result.ByClass[c.Class]
		if !ok {
			cs = &ClassScore{Class: c.Class}
			result.ByClass[c.Class] = cs
		}
		cs.Total++
		switch c.Expect {
		case "positive":
			cs.Positives++
		case "negative":
			cs.Negatives++
		}
		switch outcome {
		case "TP":
			cs.TP++
		case "FP":
			cs.FP++
		case "FN":
			cs.FN++
		case "TN":
			cs.TN++
		}
	}

	// Compute metrics
	for _, cs := range result.ByClass {
		computeMetrics(cs)
	}

	// Overall
	result.Overall = ClassScore{Class: "OVERALL"}
	for _, cs := range result.ByClass {
		result.Overall.Total += cs.Total
		result.Overall.Positives += cs.Positives
		result.Overall.Negatives += cs.Negatives
		result.Overall.TP += cs.TP
		result.Overall.FP += cs.FP
		result.Overall.FN += cs.FN
		result.Overall.TN += cs.TN
	}
	computeMetrics(&result.Overall)

	return result, nil
}

func outcomeFor(expect string, matched bool) string {
	if expect == "positive" && matched {
		return "TP"
	}
	if expect == "positive" && !matched {
		return "FN"
	}
	if expect == "negative" && matched {
		return "FP"
	}
	return "TN"
}

func computeMetrics(cs *ClassScore) {
	if cs.TP+cs.FP > 0 {
		cs.Precision = float64(cs.TP) / float64(cs.TP+cs.FP)
	}
	if cs.TP+cs.FN > 0 {
		cs.Recall = float64(cs.TP) / float64(cs.TP+cs.FN)
	}
	if cs.Precision+cs.Recall > 0 {
		cs.F1 = 2 * cs.Precision * cs.Recall / (cs.Precision + cs.Recall)
	}
}

// PrintScorecard writes a formatted scorecard to stdout.
func PrintScorecard(r *BenchmarkResult) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           SentinelCore SAST Benchmark Scorecard                ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ %-20s %4s %4s %4s %4s  %8s %8s %8s ║\n",
		"Class", "TP", "FP", "FN", "TN", "Prec", "Recall", "F1")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")

	order := scorecardOrderStrings()
	for _, cls := range order {
		cs, ok := r.ByClass[cls]
		if !ok {
			continue
		}
		fmt.Printf("║ %-20s %4d %4d %4d %4d  %7.1f%% %7.1f%% %7.1f%% ║\n",
			cs.Class, cs.TP, cs.FP, cs.FN, cs.TN,
			cs.Precision*100, cs.Recall*100, cs.F1*100)
	}

	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	o := r.Overall
	fmt.Printf("║ %-20s %4d %4d %4d %4d  %7.1f%% %7.1f%% %7.1f%% ║\n",
		"OVERALL", o.TP, o.FP, o.FN, o.TN,
		o.Precision*100, o.Recall*100, o.F1*100)
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")

	// Detail: missed cases
	var missed []CaseResult
	var fps []CaseResult
	for _, c := range r.Cases {
		if c.Outcome == "FN" {
			missed = append(missed, c)
		}
		if c.Outcome == "FP" {
			fps = append(fps, c)
		}
	}
	if len(missed) > 0 {
		fmt.Println("\nMissed (False Negatives):")
		for _, m := range missed {
			fmt.Printf("  %s  %s  %s\n", m.Case.ID, m.Case.File, m.Case.Class)
		}
	}
	if len(fps) > 0 {
		fmt.Println("\nFalse Positives:")
		for _, fp := range fps {
			fmt.Printf("  %s  %s  %s  (found %d findings)\n", fp.Case.ID, fp.Case.File, fp.Case.Class, len(fp.Findings))
		}
	}

	if len(missed) == 0 && len(fps) == 0 {
		fmt.Println("\nNo false negatives. No false positives.")
	}
}

// ScorecardMarkdown returns the scorecard as a markdown table for docs.
func ScorecardMarkdown(r *BenchmarkResult) string {
	var sb strings.Builder
	sb.WriteString("# SentinelCore SAST Benchmark Scorecard\n\n")
	sb.WriteString("| Class | TP | FP | FN | TN | Precision | Recall | F1 |\n")
	sb.WriteString("|---|---|---|---|---|---|---|---|\n")

	order := scorecardOrderStrings()
	for _, cls := range order {
		cs, ok := r.ByClass[cls]
		if !ok {
			continue
		}
		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %d | %d | %.1f%% | %.1f%% | %.1f%% |\n",
			cs.Class, cs.TP, cs.FP, cs.FN, cs.TN,
			cs.Precision*100, cs.Recall*100, cs.F1*100))
	}
	o := r.Overall
	sb.WriteString(fmt.Sprintf("| **OVERALL** | **%d** | **%d** | **%d** | **%d** | **%.1f%%** | **%.1f%%** | **%.1f%%** |\n",
		o.TP, o.FP, o.FN, o.TN,
		o.Precision*100, o.Recall*100, o.F1*100))
	return sb.String()
}
