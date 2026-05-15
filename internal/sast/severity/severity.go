// Package severity owns the SentinelCore severity policy: the
// vuln_class → (severity, SLA, compliance mapping) lookup that the
// engine and the compliance scorecard read at runtime.
//
// Sprint 1.3 §1.3 / P1-3 — this PR ships the loader, validator, and
// embedded policy.yaml. Engine adoption (read Finding.Severity from
// here instead of from per-rule JSON) is a separate follow-up PR so
// the data file can be vetted before findings start carrying
// policy-derived severities to downstream alerting.
//
// Compliance hooks the field-level mapping intentionally:
//
//   - BDDKCritical: true means the class qualifies for the 24-hour
//     remediation SLA defined by BDDK Bilgi Sistemleri Yönetmeliği's
//     "kritik açık" criterion. Used by the SLA alerter (Sprint 6) to
//     escalate findings that breach the 24h threshold to operator
//     pager rotation.
//
//   - PCIDSS lists the PCI-DSS Requirement 6.5.x sub-clauses the class
//     evidences. Compliance scorecard export consumes this list to
//     demonstrate Req 6.5 coverage to auditors.
//
//   - SWIFTCSP lists SWIFT Customer Security Programme control numbers
//     (e.g. "2.7" Vulnerability Scanning). All SAST findings fall
//     under 2.7 broadly; classes with tighter mappings get explicit
//     additional control IDs.
package severity

import (
	"embed"
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/sentinelcore/sentinelcore/internal/sast/vulnclass"
)

//go:embed policy.yaml
var policyFS embed.FS

// Policy is the deserialized severity policy. Loaded once at startup
// via Load(); the returned pointer is meant to be cached and read
// concurrently without locking — all fields are immutable after Load
// returns.
type Policy struct {
	Version int                              `yaml:"version"`
	Classes map[vulnclass.VulnClass]ClassRow `yaml:"vuln_classes"`
}

// ClassRow is the per-vuln_class severity + SLA + compliance record.
// SLA hours are absolute (not relative to severity); a low-severity
// class can still have a tight SLA if compliance demands it, and a
// high-severity class can have a loose SLA if the realistic exploit
// path is gated by other controls. Keep them independent.
type ClassRow struct {
	Severity   string     `yaml:"severity"`
	SLAHours   int        `yaml:"sla_hours"`
	CWE        []string   `yaml:"cwe"`
	Compliance Compliance `yaml:"compliance"`
}

// Compliance bundles the per-class mapping to the three frameworks
// the SentinelCore severity policy currently models. Adding a new
// framework (e.g. ISO 27001:2022 Annex A) is a schema change: add a
// field here, populate per row in policy.yaml, ship a migration in
// the same PR.
type Compliance struct {
	BDDKCritical bool     `yaml:"bddk_critical"`
	PCIDSS       []string `yaml:"pci_dss"`
	SWIFTCSP     []string `yaml:"swift_csp"`
}

// validSeverities is the set of severity tokens the engine accepts.
// Matches engine.Finding.Severity contract (critical|high|medium|low|info).
var validSeverities = map[string]struct{}{
	"critical": {},
	"high":     {},
	"medium":   {},
	"low":      {},
	"info":     {},
}

// Load reads, parses, and validates the embedded policy.yaml. Returns
// a non-nil error if any of the following invariants are violated:
//
//   - YAML parse fails.
//   - version != 1 (forward compatibility — bump intentionally).
//   - Any policy key is not a valid vulnclass.VulnClass.
//   - Any registry VulnClass is missing from the policy (every
//     declared class must have a severity decision documented).
//   - Any severity field is not in {critical, high, medium, low, info}.
//   - Any sla_hours <= 0 (zero or negative SLA is meaningless).
//   - Any BDDKCritical=true row whose severity is not "critical"
//     (BDDK 24h criterion requires criticality by definition; a
//     non-critical severity here is almost certainly a copy-paste).
//
// The validation pass is fail-fast: the first invariant violation
// returns. Callers (typically the sast-worker main) treat a Load
// error as a fatal startup condition.
func Load() (*Policy, error) {
	data, err := policyFS.ReadFile("policy.yaml")
	if err != nil {
		return nil, fmt.Errorf("severity: read embedded policy.yaml: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("severity: parse policy.yaml: %w", err)
	}

	if p.Version != 1 {
		return nil, fmt.Errorf("severity: policy.yaml version %d unsupported (want 1)", p.Version)
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate runs the invariant checks described on Load. Exposed
// separately so callers that build a Policy programmatically (tests,
// future YAML-from-disk loaders for customer overrides) can check it
// before installing.
func (p *Policy) Validate() error {
	// Every policy key must be a registered vuln_class.
	for vc := range p.Classes {
		if !vulnclass.IsValid(vc) {
			return fmt.Errorf("severity: policy.yaml references unknown vuln_class %q — add it to internal/sast/vulnclass first", vc)
		}
	}

	// Every registered vuln_class must have a policy entry.
	for _, vc := range vulnclass.All() {
		if _, ok := p.Classes[vc]; !ok {
			return fmt.Errorf("severity: vuln_class %q is in the canonical registry but missing from policy.yaml", vc)
		}
	}

	// Each row's severity, SLA, and BDDK-critical-implies-critical
	// invariants.
	for vc, row := range p.Classes {
		if _, ok := validSeverities[row.Severity]; !ok {
			return fmt.Errorf("severity: vuln_class %q has invalid severity %q (want one of critical|high|medium|low|info)", vc, row.Severity)
		}
		if row.SLAHours <= 0 {
			return fmt.Errorf("severity: vuln_class %q has non-positive sla_hours %d", vc, row.SLAHours)
		}
		if row.Compliance.BDDKCritical && row.Severity != "critical" {
			return fmt.Errorf("severity: vuln_class %q is marked bddk_critical but severity is %q — BDDK kritik açık requires severity=critical", vc, row.Severity)
		}
	}
	return nil
}

// Get returns the policy row for the given vuln_class. Second return
// is false if the class is not in the policy — should only occur for
// inputs that failed IsValid in the first place; engine code paths
// validate at the boundary and never call Get with an unknown class.
func (p *Policy) Get(vc vulnclass.VulnClass) (ClassRow, bool) {
	row, ok := p.Classes[vc]
	return row, ok
}

// BDDKCriticalClasses returns the list of vuln_classes flagged
// bddk_critical=true, in canonical registry order. Used by the
// compliance scorecard export (Sprint 1.5 / Sprint 6) and by the
// 24-hour SLA alerter.
func (p *Policy) BDDKCriticalClasses() []vulnclass.VulnClass {
	var out []vulnclass.VulnClass
	for _, vc := range vulnclass.All() {
		if row, ok := p.Classes[vc]; ok && row.Compliance.BDDKCritical {
			out = append(out, vc)
		}
	}
	return out
}
