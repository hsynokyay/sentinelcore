package risk

import "testing"

func TestSeverityBase(t *testing.T) {
	cases := map[string]int{
		"critical": 60,
		"high":     45,
		"medium":   30,
		"low":      15,
		"info":     5,
		"unknown":  0,
		"":         0,
	}
	for sev, want := range cases {
		if got := SeverityBase(sev); got != want {
			t.Errorf("SeverityBase(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestComputeScore_BaseOnly(t *testing.T) {
	got := ComputeScore(ScoreInputs{Severity: "high"})
	if got.Total != 45 {
		t.Errorf("base-only total = %d, want 45", got.Total)
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("expected 1 evidence row (base), got %d", len(got.Evidence))
	}
	if got.Evidence[0].Category != "score_base" {
		t.Errorf("first evidence category = %q, want score_base", got.Evidence[0].Category)
	}
	if got.Evidence[0].Code != "SEVERITY_BASE" {
		t.Errorf("first evidence code = %q, want SEVERITY_BASE", got.Evidence[0].Code)
	}
	if got.Evidence[0].Weight == nil || *got.Evidence[0].Weight != 45 {
		t.Errorf("first evidence weight = %v, want 45", got.Evidence[0].Weight)
	}
	if got.Evidence[0].SortOrder != 0 {
		t.Errorf("first evidence sort_order = %d, want 0", got.Evidence[0].SortOrder)
	}
}

func TestComputeScore_RuntimeConfirmed(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:         "critical",
		RuntimeConfirmed: true,
	})
	if got.Total != 60+20 {
		t.Errorf("critical + runtime = %d, want 80", got.Total)
	}
	if !hasEvidenceCode(got.Evidence, "RUNTIME_CONFIRMED") {
		t.Error("missing RUNTIME_CONFIRMED evidence")
	}
}

func TestComputeScore_PublicExposure(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:         "medium",
		PublicExposure:   true,
		PublicSurfaceURL: "/api/users",
	})
	if got.Total != 30+15 {
		t.Errorf("medium + public = %d, want 45", got.Total)
	}
	if !hasEvidenceCode(got.Evidence, "PUBLIC_EXPOSURE") {
		t.Error("missing PUBLIC_EXPOSURE evidence")
	}
}

func TestComputeScore_SameRouteSameParamDASTOnly(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:        "high",
		FingerprintKind: "dast_route",
		SameRoute:       true,
		SameParam:       true,
		CanonicalRoute:  "/api/users",
		CanonicalParam:  "id",
	})
	if got.Total != 45+5+5 {
		t.Errorf("high + route + param = %d, want 55", got.Total)
	}
	if !hasEvidenceCode(got.Evidence, "SAME_ROUTE") {
		t.Error("missing SAME_ROUTE evidence")
	}
	if !hasEvidenceCode(got.Evidence, "SAME_PARAM") {
		t.Error("missing SAME_PARAM evidence")
	}
}

func TestComputeScore_SameRouteIgnoredForSAST(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:        "high",
		FingerprintKind: "sast_file",
		SameRoute:       true, // should be ignored
		SameParam:       true, // should be ignored
	})
	if got.Total != 45 {
		t.Errorf("SAST cluster should ignore route/param boosts, got %d", got.Total)
	}
	if hasEvidenceCode(got.Evidence, "SAME_ROUTE") {
		t.Error("SAST cluster should not emit SAME_ROUTE evidence")
	}
}

func TestComputeScore_MaxReachable_CapAt100(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:         "critical",
		RuntimeConfirmed: true,
		PublicExposure:   true,
		FingerprintKind:  "dast_route",
		SameRoute:        true,
		SameParam:        true,
	})
	if got.Total != 100 {
		t.Errorf("fully boosted critical = %d, want 100 (capped)", got.Total)
	}
}

func TestComputeScore_EvidenceSortOrder(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:         "critical",
		RuntimeConfirmed: true,
		PublicExposure:   true,
		FingerprintKind:  "dast_route",
		SameRoute:        true,
		SameParam:        true,
	})
	// Evidence must be in sort_order: base=0, runtime=10, public=20, route=30, param=40
	wantCodes := []string{
		"SEVERITY_BASE", "RUNTIME_CONFIRMED", "PUBLIC_EXPOSURE",
		"SAME_ROUTE", "SAME_PARAM",
	}
	if len(got.Evidence) != len(wantCodes) {
		t.Fatalf("got %d evidence rows, want %d", len(got.Evidence), len(wantCodes))
	}
	for i, want := range wantCodes {
		if got.Evidence[i].Code != want {
			t.Errorf("evidence[%d].Code = %q, want %q", i, got.Evidence[i].Code, want)
		}
		if got.Evidence[i].SortOrder != i*10 {
			t.Errorf("evidence[%d].SortOrder = %d, want %d", i, got.Evidence[i].SortOrder, i*10)
		}
	}
}

func hasEvidenceCode(rows []Evidence, code string) bool {
	for _, e := range rows {
		if e.Code == code {
			return true
		}
	}
	return false
}
