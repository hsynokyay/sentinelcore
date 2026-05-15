package audit

import (
	"testing"
	"time"

	pkgaudit "github.com/sentinelcore/sentinelcore/pkg/audit"
)

func TestActionToEventType(t *testing.T) {
	cases := map[pkgaudit.Action]struct {
		event string
		ok    bool
	}{
		pkgaudit.RiskCreated:           {"created", true},
		pkgaudit.RiskSeenAgain:         {"seen_again", true},
		pkgaudit.RiskScoreChanged:      {"score_changed", true},
		pkgaudit.RiskStatusChanged:     {"status_changed", true},
		pkgaudit.RiskResolved:          {"resolved", true},
		pkgaudit.RiskNoteAdded:         {"note_added", true},
		pkgaudit.CorrelationRebuildTrigg: {"", false}, // not per-risk
		pkgaudit.AuthLoginSucceeded:    {"", false},
		pkgaudit.Action("risk.unknown"):{"", false},
	}
	for a, want := range cases {
		got, ok := actionToEventType(a)
		if got != want.event || ok != want.ok {
			t.Errorf("actionToEventType(%q) = (%q, %v), want (%q, %v)",
				a, got, ok, want.event, want.ok)
		}
	}
}

func TestAssessMateriality_ScoreChanged(t *testing.T) {
	// score delta ≥ 0.5 → material; less → skip.
	cases := []struct {
		before, after float64
		material      bool
	}{
		{7.0, 7.4, false},   // 0.4 — noise
		{7.0, 7.5, true},    // 0.5 — boundary material
		{7.0, 8.0, true},    // large jump
		{8.0, 7.0, true},    // drop — abs delta
		{7.0, 7.0, false},   // no change
		{5.2, 5.8, true},    // 0.6
		{5.2, 5.3, false},   // 0.1
	}
	for _, c := range cases {
		before := map[string]any{"score": c.before}
		after := map[string]any{"score": c.after}
		got := assessMateriality("score_changed", before, after, nil)
		if got != c.material {
			t.Errorf("score %.1f→%.1f: got material=%v, want %v",
				c.before, c.after, got, c.material)
		}
	}
}

func TestAssessMateriality_SeenAgain(t *testing.T) {
	longAgo := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	recent := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano)
	border := time.Now().Add(-7 * 24 * time.Hour).Add(time.Minute).UTC().Format(time.RFC3339Nano) // 7d + 1min ago

	cases := []struct {
		last     string
		material bool
	}{
		{"", true},          // missing → material
		{longAgo, true},     // 30d ago → material
		{recent, false},     // 2h ago → noise
		{border, false},     // 7d - 1min (just under threshold) → noise
		{"garbage", true},   // unparseable → material
	}
	for _, c := range cases {
		d := map[string]any{}
		if c.last != "" {
			d["last_seen"] = c.last
		}
		got := assessMateriality("seen_again", nil, nil, d)
		if got != c.material {
			t.Errorf("seen_again last=%q: got material=%v, want %v",
				c.last, got, c.material)
		}
	}
}

func TestAssessMateriality_AlwaysMaterialEvents(t *testing.T) {
	for _, ev := range []string{
		"created", "status_changed", "resolved", "reopened",
		"muted", "unmuted", "assigned", "note_added",
		"relation_added", "relation_removed", "evidence_changed",
	} {
		if !assessMateriality(ev, nil, nil, nil) {
			t.Errorf("event_type %q should always be material", ev)
		}
	}
}

func TestDetailsMap_HandlesShapes(t *testing.T) {
	if m := detailsMap(nil); m != nil {
		t.Errorf("nil: want nil, got %v", m)
	}
	if m := detailsMap(map[string]any{"a": 1}); m["a"] != 1 {
		t.Errorf("direct map: lost field: %v", m)
	}
	type S struct {
		A int    `json:"a"`
		B string `json:"b"`
	}
	if m := detailsMap(S{A: 1, B: "x"}); m["b"] != "x" {
		t.Errorf("struct roundtrip: %v", m)
	}
}

func TestBeforeAfter(t *testing.T) {
	d := map[string]any{
		"before": map[string]any{"score": 7.0},
		"after":  map[string]any{"score": 8.5},
	}
	b, a := beforeAfter(d)
	if b["score"] != 7.0 || a["score"] != 8.5 {
		t.Errorf("b=%v a=%v", b, a)
	}

	// Missing fields yield empty maps, never nil.
	b2, a2 := beforeAfter(map[string]any{})
	if b2 == nil || a2 == nil {
		t.Errorf("expected non-nil maps for empty input")
	}
}
