package governance

import (
	"errors"
	"testing"
	"time"
)

var created = time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)

func mkPolicy(remDays, warnDays int) SLAPolicy {
	return SLAPolicy{
		Severity:        "critical",
		RemediationDays: remDays,
		WarnDaysBefore:  warnDays,
	}
}

func TestComputeDeadlines_HappyPath(t *testing.T) {
	d, w, err := ComputeDeadlines(created, mkPolicy(7, 2))
	if err != nil {
		t.Fatal(err)
	}
	wantD := created.Add(7 * 24 * time.Hour)
	wantW := wantD.Add(-2 * 24 * time.Hour)
	if !d.Equal(wantD) || !w.Equal(wantW) {
		t.Errorf("deadline=%v want %v; warn=%v want %v", d, wantD, w, wantW)
	}
}

func TestComputeDeadlines_WarnClampsToCreated(t *testing.T) {
	// warn_days_before > remediation_days: warn collapses to created.
	_, w, err := ComputeDeadlines(created, mkPolicy(3, 10))
	if err != nil {
		t.Fatal(err)
	}
	if !w.Equal(created) {
		t.Errorf("warn should clamp to created; got %v", w)
	}
}

func TestComputeDeadlines_Rejects(t *testing.T) {
	for _, p := range []SLAPolicy{
		{RemediationDays: 0, WarnDaysBefore: 1},
		{RemediationDays: -5, WarnDaysBefore: 1},
		{RemediationDays: 10, WarnDaysBefore: -1},
	} {
		if _, _, err := ComputeDeadlines(created, p); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("policy %+v: want ErrInvalidPolicy, got %v", p, err)
		}
	}
}

func TestDeriveStatus(t *testing.T) {
	dl := created.Add(7 * 24 * time.Hour)
	warn := dl.Add(-2 * 24 * time.Hour)
	resolved := created.Add(1 * time.Hour)
	breached := dl.Add(1 * time.Minute)

	cases := []struct {
		name       string
		now        time.Time
		resolved   *time.Time
		breached   *time.Time
		want       SLAStatus
	}{
		{"on_track at creation", created, nil, nil, SLAOnTrack},
		{"on_track 1 day later", created.Add(24 * time.Hour), nil, nil, SLAOnTrack},
		{"due_soon at warn_at", warn, nil, nil, SLADueSoon},
		{"overdue at deadline", dl, nil, nil, SLAOverdue},
		{"overdue past deadline", dl.Add(time.Hour), nil, nil, SLAOverdue},
		{"resolved beats overdue", dl.Add(time.Hour), &resolved, nil, SLAResolved},
		{"breached flag wins even before deadline", warn, nil, &breached, SLAOverdue},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DeriveStatus(c.now, dl, warn, c.resolved, c.breached)
			if got != c.want {
				t.Errorf("got %s want %s", got, c.want)
			}
		})
	}
}

func TestShouldEscalate(t *testing.T) {
	now := created.Add(10 * 24 * time.Hour)
	breached := created.Add(5 * 24 * time.Hour)        // 5d ago
	recentBreach := created.Add(10*24*time.Hour - 30*time.Minute) // 30 min ago
	escalated := created.Add(5*24*time.Hour + time.Hour)

	hrs := 48
	p := SLAPolicy{EscalateAfterHours: &hrs}

	// Breached >48h ago, not yet escalated → escalate.
	if !ShouldEscalate(now, p, &breached, nil) {
		t.Error("expected escalation")
	}
	// Already escalated → no.
	if ShouldEscalate(now, p, &breached, &escalated) {
		t.Error("already escalated, should not re-escalate")
	}
	// Breach only 30min old → no.
	if ShouldEscalate(now, p, &recentBreach, nil) {
		t.Error("too recent, should not escalate yet")
	}
	// No policy threshold → no.
	if ShouldEscalate(now, SLAPolicy{}, &breached, nil) {
		t.Error("no threshold, should not escalate")
	}
	// No breach → no.
	if ShouldEscalate(now, p, nil, nil) {
		t.Error("no breach, should not escalate")
	}
}
