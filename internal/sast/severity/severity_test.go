package severity

import (
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/sast/vulnclass"
)

// TestLoad_EmbeddedPolicy verifies that the embedded policy.yaml
// parses, validates, and covers every canonical vuln_class. This is
// the cross-validation contract: every constant in
// internal/sast/vulnclass must have a row in policy.yaml, and every
// row in policy.yaml must reference a registered vuln_class. The PR
// description for Sprint 1.3 §1.3 P1-3 made this the headline contract.
func TestLoad_EmbeddedPolicy(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Version != 1 {
		t.Errorf("policy version: got %d, want 1", p.Version)
	}
	if got, want := len(p.Classes), len(vulnclass.All()); got != want {
		t.Errorf("policy class count: got %d, want %d (registry size)", got, want)
	}
}

// TestPolicy_AllRegistryClassesPresent guards the "every registry
// class must have a policy row" invariant explicitly. Distinct from
// the load-time validator so an author can see which class is missing
// at test time rather than reading a wrapped error.
func TestPolicy_AllRegistryClassesPresent(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, vc := range vulnclass.All() {
		if _, ok := p.Classes[vc]; !ok {
			t.Errorf("vuln_class %q is in vulnclass.All() but missing from policy.yaml", vc)
		}
	}
}

// TestPolicy_NoOrphanedKeys is the symmetric invariant: every key in
// policy.yaml must be a registered vuln_class. Catches typos and
// drifted-out-of-sync deletions in the registry.
func TestPolicy_NoOrphanedKeys(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for vc := range p.Classes {
		if !vulnclass.IsValid(vc) {
			t.Errorf("policy.yaml has key %q which is not in vulnclass registry", vc)
		}
	}
}

// TestPolicy_BDDKCriticalImpliesCriticalSeverity verifies the
// BDDK-Bilgi-Sistemleri-Yönetmeliği invariant: every row marked
// bddk_critical must carry severity=critical (because the 24h
// remediation SLA is defined for kritik açık). The load-time
// validator catches this too; this test asserts the data file
// satisfies it today, with a clear failure message per class.
func TestPolicy_BDDKCriticalImpliesCriticalSeverity(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for vc, row := range p.Classes {
		if row.Compliance.BDDKCritical && row.Severity != "critical" {
			t.Errorf("vuln_class %q: bddk_critical=true but severity=%q (BDDK kritik açık requires severity=critical)", vc, row.Severity)
		}
	}
}

// TestPolicy_SLAHoursPositive — every SLA must be a positive integer.
// Zero or negative SLAs are nonsensical and would crash the Sprint 6
// alerter that does `created_at + sla_hours`.
func TestPolicy_SLAHoursPositive(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for vc, row := range p.Classes {
		if row.SLAHours <= 0 {
			t.Errorf("vuln_class %q: sla_hours=%d must be > 0", vc, row.SLAHours)
		}
	}
}

// TestPolicy_CWEFormat — every CWE entry must look like "CWE-<digits>".
// Catches typos like "CVE-89" or "CWE89" early.
func TestPolicy_CWEFormat(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for vc, row := range p.Classes {
		for _, cwe := range row.CWE {
			if !strings.HasPrefix(cwe, "CWE-") || len(cwe) < 5 {
				t.Errorf("vuln_class %q: malformed CWE entry %q (want CWE-NNN)", vc, cwe)
			}
		}
	}
}

// TestPolicy_PCIDSSFormat — PCI-DSS entries must look like Req 6.5.x
// (or just the number, no whitespace). Currently we only model 6.5;
// when Req 8 / Req 10 mappings land, relax this assertion.
func TestPolicy_PCIDSSFormat(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for vc, row := range p.Classes {
		for _, req := range row.Compliance.PCIDSS {
			if !strings.HasPrefix(req, "6.5") {
				t.Errorf("vuln_class %q: unexpected PCI-DSS entry %q (currently only Req 6.5.x is modeled)", vc, req)
			}
		}
	}
}

// TestPolicy_SWIFTCSPAt27 — SAST findings fall under SWIFT CSP control
// 2.7 (Vulnerability Scanning) by definition; every row must include
// 2.7. Additional controls (5.1 access control, 4.1 password policy)
// may also be present for relevant classes.
func TestPolicy_SWIFTCSPAt27(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for vc, row := range p.Classes {
		has27 := false
		for _, c := range row.Compliance.SWIFTCSP {
			if c == "2.7" {
				has27 = true
				break
			}
		}
		if !has27 {
			t.Errorf("vuln_class %q: missing SWIFT CSP control 2.7 — every SAST class falls under 2.7", vc)
		}
	}
}

// TestPolicy_Get_KnownClassReturnsRow — Get path on a known class
// returns the row, ok=true.
func TestPolicy_Get_KnownClassReturnsRow(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	row, ok := p.Get(vulnclass.SQLInjection)
	if !ok {
		t.Fatal("Get(SQLInjection) returned ok=false")
	}
	if row.Severity != "critical" || row.SLAHours != 24 {
		t.Errorf("SQLInjection row: got severity=%q sla=%d; want critical/24", row.Severity, row.SLAHours)
	}
	if !row.Compliance.BDDKCritical {
		t.Error("SQLInjection should be bddk_critical=true")
	}
}

// TestPolicy_BDDKCriticalClasses returns the curated critical set in
// canonical registry order. Smoke-checks that SQL/CMD/secret/deser
// are in, that XSS and open_redirect are not.
func TestPolicy_BDDKCriticalClasses(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	critical := p.BDDKCriticalClasses()

	mustHave := []vulnclass.VulnClass{
		vulnclass.SQLInjection,
		vulnclass.CommandInjection,
		vulnclass.HardcodedSecret,
		vulnclass.UnsafeDeserialization,
		vulnclass.AuthBypass,
	}
	mustNotHave := []vulnclass.VulnClass{
		vulnclass.XSS,
		vulnclass.OpenRedirect,
		vulnclass.InsecureCookie,
	}
	set := make(map[vulnclass.VulnClass]struct{}, len(critical))
	for _, vc := range critical {
		set[vc] = struct{}{}
	}
	for _, vc := range mustHave {
		if _, ok := set[vc]; !ok {
			t.Errorf("BDDKCriticalClasses should include %q", vc)
		}
	}
	for _, vc := range mustNotHave {
		if _, ok := set[vc]; ok {
			t.Errorf("BDDKCriticalClasses must not include %q (severity is not critical)", vc)
		}
	}
}
