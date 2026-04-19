package risk

import "testing"

func TestClassifyRelation_RuntimeConfirmation_BaseConfidence(t *testing.T) {
	sast := &Cluster{ID: "a", FingerprintKind: "sast_file", CWEID: 89, VulnClass: "sql_injection"}
	dast := &Cluster{ID: "b", FingerprintKind: "dast_route", CWEID: 89, VulnClass: "sql_injection"}

	rt, conf, _ := ClassifyRelation(sast, dast, false)
	if rt != "runtime_confirmation" {
		t.Errorf("rt = %q, want runtime_confirmation", rt)
	}
	if conf != 0.80 {
		t.Errorf("base confidence = %v, want 0.80", conf)
	}
}

func TestClassifyRelation_RuntimeConfirmation_OWASPBonus(t *testing.T) {
	sast := &Cluster{FingerprintKind: "sast_file", CWEID: 89, OWASPCategory: "A03:2021"}
	dast := &Cluster{FingerprintKind: "dast_route", CWEID: 89, OWASPCategory: "A03:2021"}

	_, conf, _ := ClassifyRelation(sast, dast, false)
	if conf != 0.90 {
		t.Errorf("confidence with OWASP match = %v, want 0.90", conf)
	}
}

func TestClassifyRelation_RuntimeConfirmation_NoOWASPBonus_Empty(t *testing.T) {
	sast := &Cluster{FingerprintKind: "sast_file", CWEID: 89, OWASPCategory: ""}
	dast := &Cluster{FingerprintKind: "dast_route", CWEID: 89, OWASPCategory: ""}

	_, conf, _ := ClassifyRelation(sast, dast, false)
	if conf != 0.80 {
		t.Errorf("empty OWASP shouldn't trigger bonus, got %v", conf)
	}
}

func TestClassifyRelation_RuntimeConfirmation_NoOWASPBonus_Mismatch(t *testing.T) {
	sast := &Cluster{FingerprintKind: "sast_file", CWEID: 89, OWASPCategory: "A03:2021"}
	dast := &Cluster{FingerprintKind: "dast_route", CWEID: 89, OWASPCategory: "A01:2021"}

	_, conf, _ := ClassifyRelation(sast, dast, false)
	if conf != 0.80 {
		t.Errorf("mismatched OWASP shouldn't bonus, got %v", conf)
	}
}

func TestClassifyRelation_SameCWE(t *testing.T) {
	a := &Cluster{FingerprintKind: "sast_file", CWEID: 89}
	b := &Cluster{FingerprintKind: "sast_file", CWEID: 89}

	rt, conf, _ := ClassifyRelation(a, b, false)
	if rt != "same_cwe" || conf != 0.30 {
		t.Errorf("same_cwe: got (%q, %v), want (same_cwe, 0.30)", rt, conf)
	}
}

func TestClassifyRelation_RelatedSurface(t *testing.T) {
	a := &Cluster{FingerprintKind: "dast_route", CWEID: 89}
	b := &Cluster{FingerprintKind: "dast_route", CWEID: 22}

	// With sharesSurface = true
	rt, conf, _ := ClassifyRelation(a, b, true)
	if rt != "related_surface" || conf != 0.60 {
		t.Errorf("related_surface: got (%q, %v), want (related_surface, 0.60)", rt, conf)
	}
}

func TestClassifyRelation_NoRelation(t *testing.T) {
	a := &Cluster{FingerprintKind: "sast_file", CWEID: 89}
	b := &Cluster{FingerprintKind: "dast_route", CWEID: 22} // different CWE

	rt, _, _ := ClassifyRelation(a, b, false)
	if rt != "" {
		t.Errorf("unrelated clusters produced relation %q", rt)
	}
}

func TestCanonicalizePair(t *testing.T) {
	// Smaller UUID becomes source.
	src, tgt := CanonicalizePair("bbb", "aaa")
	if src != "aaa" || tgt != "bbb" {
		t.Errorf("got (%q, %q), want (aaa, bbb)", src, tgt)
	}
	src, tgt = CanonicalizePair("aaa", "bbb")
	if src != "aaa" || tgt != "bbb" {
		t.Errorf("already canonical: got (%q, %q)", src, tgt)
	}
}
