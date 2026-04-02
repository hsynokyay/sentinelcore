package browser

import "testing"

func TestIsDestructiveAction(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{"Delete Account", true},
		{"Remove Item", true},
		{"Cancel Subscription", true},
		{"Unsubscribe from newsletter", true},
		{"Pay Now", true},
		{"Purchase", true},
		{"Transfer Funds", true},
		{"Send Message", true},
		{"Destroy Resource", true},
		{"Drop Table", true},
		{"Terminate Instance", true},
		{"Revoke Access", true},
		{"Submit Form", false},
		{"Save Changes", false},
		{"View Details", false},
		{"Login", false},
		{"Search", false},
		{"", false},
		// Case insensitive.
		{"DELETE", true},
		{"dElEtE", true},
		// Embedded keywords.
		{"click-to-delete-account", true},
		{"unsubscribe_all", true},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			got := IsDestructiveAction(tt.text)
			if got != tt.want {
				t.Errorf("IsDestructiveAction(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func TestDestructiveKeywordsNotEmpty(t *testing.T) {
	if len(DestructiveKeywords) == 0 {
		t.Fatal("DestructiveKeywords must not be empty")
	}
}
