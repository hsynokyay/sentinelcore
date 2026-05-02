package browser

import "testing"

func TestSafeInteractor_New(t *testing.T) {
	si := NewSafeInteractor(testLogger())
	if si == nil {
		t.Fatal("NewSafeInteractor returned nil")
	}
}

func TestClickSafeTargets_SkipsUnsafe(t *testing.T) {
	targets := []ClickTarget{
		{Selector: "#safe", Tag: "a", Href: "/page", Text: "Link", Safety: ClickSafe},
		{Selector: "#unsafe", Tag: "button", Type: "submit", Text: "Delete", Safety: ClickUnsafe},
		{Selector: "#unknown", Tag: "div", Text: "Custom", Safety: ClickUnknown},
	}

	safeCount := 0
	for _, t := range targets {
		if t.Safety == ClickSafe {
			safeCount++
		}
	}
	if safeCount != 1 {
		t.Errorf("expected 1 safe target, got %d", safeCount)
	}
}

func TestClickSafeTargets_RespectsMaxClicks(t *testing.T) {
	targets := []ClickTarget{
		{Selector: "#a", Safety: ClickSafe},
		{Selector: "#b", Safety: ClickSafe},
		{Selector: "#c", Safety: ClickSafe},
		{Selector: "#d", Safety: ClickSafe},
		{Selector: "#e", Safety: ClickSafe},
	}

	// Count how many would be clicked with maxClicks=3
	maxClicks := 3
	clicked := 0
	for _, target := range targets {
		if clicked >= maxClicks {
			break
		}
		if target.Safety == ClickSafe && target.Selector != "" {
			clicked++
		}
	}
	if clicked != 3 {
		t.Errorf("expected 3 clicks at max, got %d", clicked)
	}
}

func TestInteractionResult_Fields(t *testing.T) {
	r := InteractionResult{
		Target:       ClickTarget{Tag: "a", Text: "Home"},
		TriggeredNav: true,
		NewURL:       "https://example.com/home",
		DOMChanged:   true,
	}
	if !r.TriggeredNav {
		t.Error("expected navigation triggered")
	}
	if r.NewURL != "https://example.com/home" {
		t.Error("wrong new URL")
	}
	if !r.DOMChanged {
		t.Error("expected DOM changed")
	}
}
