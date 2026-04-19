package browser

import "testing"

func TestClassifyClick(t *testing.T) {
	tests := []struct {
		name   string
		target ClickTarget
		want   ClickSafety
	}{
		// Safe: navigation elements
		{
			"anchor with href",
			ClickTarget{Tag: "a", Href: "/page", Text: "Next Page"},
			ClickSafe,
		},
		{
			"tab role",
			ClickTarget{Tag: "button", Role: "tab", Text: "Settings", Type: "button"},
			ClickSafe,
		},
		{
			"menuitem role",
			ClickTarget{Tag: "li", Role: "menuitem", Text: "Dashboard"},
			ClickSafe,
		},
		{
			"nav-link class",
			ClickTarget{Tag: "a", Classes: "nav-link active", Href: "#", Text: "Home"},
			ClickSafe,
		},
		{
			"accordion class",
			ClickTarget{Tag: "div", Classes: "accordion-header", Text: "Section 1"},
			ClickSafe,
		},
		{
			"dropdown-toggle class",
			ClickTarget{Tag: "button", Classes: "dropdown-toggle", Type: "button", Text: "Menu"},
			ClickSafe,
		},
		{
			"button type=button (non-submitting)",
			ClickTarget{Tag: "button", Type: "button", Text: "Show More"},
			ClickSafe,
		},
		{
			"pagination class",
			ClickTarget{Tag: "a", Classes: "pagination-link", Href: "?page=2", Text: "2"},
			ClickSafe,
		},
		{
			"switch role",
			ClickTarget{Tag: "button", Role: "switch", Text: "Dark mode"},
			ClickSafe,
		},

		// Unsafe: destructive or submitting
		{
			"delete button",
			ClickTarget{Tag: "button", Text: "Delete Account", Type: "button"},
			ClickUnsafe,
		},
		{
			"remove link",
			ClickTarget{Tag: "a", Href: "/remove", Text: "Remove Item"},
			ClickUnsafe,
		},
		{
			"submit button",
			ClickTarget{Tag: "button", Type: "submit", Text: "Submit"},
			ClickUnsafe,
		},
		{
			"input submit",
			ClickTarget{Tag: "input", Type: "submit", Text: "Send"},
			ClickUnsafe,
		},
		{
			"file input",
			ClickTarget{Tag: "input", Type: "file", Text: "Upload"},
			ClickUnsafe,
		},
		{
			"reset button",
			ClickTarget{Tag: "input", Type: "reset", Text: "Clear"},
			ClickUnsafe,
		},
		{
			"button no type (default submit in form)",
			ClickTarget{Tag: "button", Type: "", Text: "Save"},
			ClickUnsafe,
		},
		{
			"pay button",
			ClickTarget{Tag: "button", Type: "button", Text: "Pay Now"},
			ClickUnsafe,
		},
		{
			"cancel action",
			ClickTarget{Tag: "a", Href: "/cancel", Text: "Cancel Subscription"},
			ClickUnsafe,
		},

		// Unknown
		{
			"div with onclick no role",
			ClickTarget{Tag: "div", Text: "Click me", Classes: "custom-widget"},
			ClickUnknown,
		},
		{
			"span no context",
			ClickTarget{Tag: "span", Text: "Something"},
			ClickUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyClick(tt.target)
			if got != tt.want {
				t.Errorf("ClassifyClick(%+v) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestClickSafety_String(t *testing.T) {
	if ClickSafe.String() != "safe" {
		t.Error("ClickSafe should be 'safe'")
	}
	if ClickUnsafe.String() != "unsafe" {
		t.Error("ClickUnsafe should be 'unsafe'")
	}
	if ClickUnknown.String() != "unknown" {
		t.Error("ClickUnknown should be 'unknown'")
	}
}

func TestClassifyClick_DestructiveKeywordsOverrideSafeRole(t *testing.T) {
	// Even with a safe role, destructive text makes it unsafe
	ct := ClickTarget{
		Tag:  "button",
		Role: "tab",
		Text: "Delete All",
		Type: "button",
	}
	if ClassifyClick(ct) != ClickUnsafe {
		t.Error("destructive keyword should override safe role")
	}
}

func TestClassifyClick_CaseInsensitive(t *testing.T) {
	ct := ClickTarget{Tag: "button", Type: "SUBMIT", Text: "Go"}
	if ClassifyClick(ct) != ClickUnsafe {
		t.Error("type check should be case-insensitive")
	}
}
