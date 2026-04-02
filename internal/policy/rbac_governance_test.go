package policy

import "testing"

func TestGovernancePermissions(t *testing.T) {
	tests := []struct {
		role       string
		permission string
		want       bool
	}{
		// governance.settings
		{"platform_admin", "governance.settings.read", true},
		{"security_admin", "governance.settings.read", true},
		{"appsec_analyst", "governance.settings.read", false},
		{"auditor", "governance.settings.read", true},
		{"platform_admin", "governance.settings.write", true},
		{"security_admin", "governance.settings.write", true},
		{"appsec_analyst", "governance.settings.write", false},

		// governance.approvals
		{"platform_admin", "governance.approvals.read", true},
		{"security_admin", "governance.approvals.read", true},
		{"appsec_analyst", "governance.approvals.read", true},
		{"auditor", "governance.approvals.read", true},
		{"platform_admin", "governance.approvals.decide", true},
		{"security_admin", "governance.approvals.decide", true},
		{"appsec_analyst", "governance.approvals.decide", false},
		{"auditor", "governance.approvals.decide", false},

		// emergency stop
		{"platform_admin", "governance.emergency_stop.activate", true},
		{"security_admin", "governance.emergency_stop.activate", true},
		{"appsec_analyst", "governance.emergency_stop.activate", false},
		{"platform_admin", "governance.emergency_stop.lift", true},
		{"security_admin", "governance.emergency_stop.lift", false},

		// findings extensions
		{"platform_admin", "findings.legal_hold", true},
		{"security_admin", "findings.legal_hold", true},
		{"appsec_analyst", "findings.legal_hold", false},

		// webhooks
		{"platform_admin", "webhooks.read", true},
		{"security_admin", "webhooks.read", true},
		{"appsec_analyst", "webhooks.read", true},
		{"auditor", "webhooks.read", true},
		{"platform_admin", "webhooks.manage", true},
		{"security_admin", "webhooks.manage", true},
		{"appsec_analyst", "webhooks.manage", false},

		// retention
		{"platform_admin", "retention.read", true},
		{"security_admin", "retention.read", true},
		{"auditor", "retention.read", true},
		{"platform_admin", "retention.manage", true},
		{"security_admin", "retention.manage", false},

		// reports
		{"platform_admin", "reports.read", true},
		{"security_admin", "reports.read", true},
		{"appsec_analyst", "reports.read", true},
		{"auditor", "reports.read", true},
	}
	for _, tt := range tests {
		t.Run(tt.role+"/"+tt.permission, func(t *testing.T) {
			got := Evaluate(tt.role, tt.permission)
			if got != tt.want {
				t.Errorf("Evaluate(%q, %q) = %v, want %v", tt.role, tt.permission, got, tt.want)
			}
		})
	}
}
