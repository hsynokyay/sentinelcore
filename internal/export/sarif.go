package export

import (
	"encoding/json"

	"github.com/sentinelcore/sentinelcore/internal/remediation"
	"fmt"
	"strings"
)

// SARIF 2.1.0 types — minimal subset for generation.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMsg          `json:"shortDescription"`
	FullDescription  *sarifMsg         `json:"fullDescription,omitempty"`
	Help             *sarifHelp        `json:"help,omitempty"`
	DefaultConfig    sarifDefaultCfg   `json:"defaultConfiguration"`
	Properties       map[string]any    `json:"properties,omitempty"`
}

type sarifMsg struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifDefaultCfg struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID       string              `json:"ruleId"`
	RuleIndex    int                 `json:"ruleIndex"`
	Level        string              `json:"level"`
	Message      sarifMsg            `json:"message"`
	Locations    []sarifLocation     `json:"locations"`
	Fingerprints map[string]string   `json:"fingerprints,omitempty"`
	CodeFlows    []sarifCodeFlow     `json:"codeFlows,omitempty"`
}

type sarifLocation struct {
	Physical *sarifPhysical `json:"physicalLocation,omitempty"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
	Region   *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifTFLocation `json:"locations"`
}

type sarifTFLocation struct {
	Location sarifLocation `json:"location"`
	Kinds    []string      `json:"kinds,omitempty"`
	Message  *sarifMsg     `json:"message,omitempty"`
}

type sarifInvocation struct {
	Success   bool    `json:"executionSuccessful"`
	StartTime *string `json:"startTimeUtc,omitempty"`
	EndTime   *string `json:"endTimeUtc,omitempty"`
}

// FindingSARIF generates a SARIF 2.1.0 log for a single finding.
func FindingSARIF(f FindingData) ([]byte, error) {
	rule := buildRule(f)
	result := buildResult(f, 0)
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "SentinelCore", Version: "1.0.0", InformationURI: "https://sentinelcore.resiliencetech.com.tr", Rules: []sarifRule{rule}}},
			Results: []sarifResult{result},
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

// ScanSARIF generates a SARIF 2.1.0 log for an entire scan.
func ScanSARIF(d ScanData) ([]byte, error) {
	ruleMap := map[string]int{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range d.Findings {
		rid := effectiveRuleID(f)
		idx, ok := ruleMap[rid]
		if !ok {
			idx = len(rules)
			ruleMap[rid] = idx
			rules = append(rules, buildRule(f))
		}
		results = append(results, buildResult(f, idx))
	}

	run := sarifRun{
		Tool:    sarifTool{Driver: sarifDriver{Name: "SentinelCore", Version: "1.0.0", InformationURI: "https://sentinelcore.resiliencetech.com.tr", Rules: rules}},
		Results: results,
	}

	if d.StartedAt != nil {
		inv := sarifInvocation{Success: d.Status == "completed"}
		s := d.StartedAt.Format("2006-01-02T15:04:05Z")
		inv.StartTime = &s
		if d.FinishedAt != nil {
			e := d.FinishedAt.Format("2006-01-02T15:04:05Z")
			inv.EndTime = &e
		}
		run.Invocations = []sarifInvocation{inv}
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	return json.MarshalIndent(log, "", "  ")
}

func buildRule(f FindingData) sarifRule {
	rid := effectiveRuleID(f)
	r := sarifRule{
		ID:            rid,
		Name:          rid,
		ShortDescription: sarifMsg{Text: f.Title},
		DefaultConfig: sarifDefaultCfg{Level: sevToLevel(f.Severity)},
	}
	if f.Description != "" {
		r.FullDescription = &sarifMsg{Text: f.Description}
	}
	if f.Remediation != nil {
		r.Help = &sarifHelp{
			Text:     f.Remediation.HowToFix,
			Markdown: buildHelpMD(f),
		}
		props := map[string]any{"tags": []string{f.FindingType, f.Severity}}
		cwe := extractCWE(f.Remediation)
		if len(cwe) > 0 {
			props["cwe"] = cwe
		}
		r.Properties = props
	}
	return r
}

func buildResult(f FindingData, ruleIdx int) sarifResult {
	r := sarifResult{
		RuleID:    effectiveRuleID(f),
		RuleIndex: ruleIdx,
		Level:     sevToLevel(f.Severity),
		Message:   sarifMsg{Text: f.Title},
		Locations: []sarifLocation{buildLoc(f)},
	}
	if f.ID != "" {
		r.Fingerprints = map[string]string{"sentinelcore/v1": f.ID}
	}
	if len(f.TaintPaths) > 1 {
		var locs []sarifTFLocation
		for _, s := range f.TaintPaths {
			locs = append(locs, sarifTFLocation{
				Location: sarifLocation{Physical: &sarifPhysical{
					Artifact: sarifArtifact{URI: s.FilePath},
					Region:   &sarifRegion{StartLine: s.LineStart},
				}},
				Kinds:   []string{s.StepKind},
				Message: &sarifMsg{Text: s.Detail},
			})
		}
		r.CodeFlows = []sarifCodeFlow{{ThreadFlows: []sarifThreadFlow{{Locations: locs}}}}
	}
	return r
}

func buildLoc(f FindingData) sarifLocation {
	uri := f.FilePath
	if uri == "" {
		uri = f.URL
	}
	if uri == "" {
		uri = "unknown"
	}
	line := f.LineStart
	if line < 1 {
		line = 1
	}
	return sarifLocation{Physical: &sarifPhysical{
		Artifact: sarifArtifact{URI: uri},
		Region:   &sarifRegion{StartLine: line},
	}}
}

func buildHelpMD(f FindingData) string {
	if f.Remediation == nil {
		return ""
	}
	r := f.Remediation
	var b strings.Builder
	b.WriteString("## " + r.Title + "\n\n")
	b.WriteString(r.Summary + "\n\n")
	b.WriteString("### How to Fix\n\n")
	b.WriteString(r.HowToFix + "\n")
	if r.SafeExample != "" {
		b.WriteString("\n### Safe Example\n```\n" + r.SafeExample + "\n```\n")
	}
	return b.String()
}

func extractCWE(r *remediation.Pack) []string {
	var cwe []string
	for _, ref := range r.References {
		if strings.HasPrefix(ref.Title, "CWE-") {
			cwe = append(cwe, ref.Title)
		}
	}
	return cwe
}

func effectiveRuleID(f FindingData) string {
	if f.RuleID != "" {
		return f.RuleID
	}
	return fmt.Sprintf("sentinelcore/%s/%s", f.FindingType, f.Severity)
}

func sevToLevel(s string) string {
	switch s {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
