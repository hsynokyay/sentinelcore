package vuln

import "testing"

func TestMatchVersion(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		versionRange string
		ecosystem    string
		want         bool
	}{
		{
			name:         "version below upper bound",
			version:      "4.17.20",
			versionRange: "< 4.17.21",
			ecosystem:    "npm",
			want:         true,
		},
		{
			name:         "version at upper bound",
			version:      "4.17.21",
			versionRange: "< 4.17.21",
			ecosystem:    "npm",
			want:         false,
		},
		{
			name:         "version above upper bound",
			version:      "4.17.22",
			versionRange: "< 4.17.21",
			ecosystem:    "npm",
			want:         false,
		},
		{
			name:         "compound range - in range",
			version:      "1.5.0",
			versionRange: ">= 1.0.0, < 2.0.0",
			ecosystem:    "npm",
			want:         true,
		},
		{
			name:         "compound range - below lower bound",
			version:      "0.9.0",
			versionRange: ">= 1.0.0, < 2.0.0",
			ecosystem:    "npm",
			want:         false,
		},
		{
			name:         "compound range - at upper bound",
			version:      "2.0.0",
			versionRange: ">= 1.0.0, < 2.0.0",
			ecosystem:    "npm",
			want:         false,
		},
		{
			name:         "compound range - at lower bound",
			version:      "1.0.0",
			versionRange: ">= 1.0.0, < 2.0.0",
			ecosystem:    "npm",
			want:         true,
		},
		{
			name:         "all versions before fix",
			version:      "0.0.1",
			versionRange: ">= 0, < 4.17.21",
			ecosystem:    "npm",
			want:         true,
		},
		{
			name:         "exact match",
			version:      "1.0.0",
			versionRange: "= 1.0.0",
			ecosystem:    "npm",
			want:         true,
		},
		{
			name:         "exact match - no match",
			version:      "1.0.1",
			versionRange: "= 1.0.0",
			ecosystem:    "npm",
			want:         false,
		},
		{
			name:         "empty version",
			version:      "",
			versionRange: "< 4.17.21",
			ecosystem:    "npm",
			want:         false,
		},
		{
			name:         "empty range",
			version:      "1.0.0",
			versionRange: "",
			ecosystem:    "npm",
			want:         false,
		},
		{
			name:         "version with v prefix",
			version:      "v1.5.0",
			versionRange: ">= 1.0.0, < 2.0.0",
			ecosystem:    "go",
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchVersion(tt.version, tt.versionRange, tt.ecosystem)
			if got != tt.want {
				t.Errorf("MatchVersion(%q, %q, %q) = %v, want %v",
					tt.version, tt.versionRange, tt.ecosystem, got, tt.want)
			}
		})
	}
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"1.10.0", "1.9.0", 1},
		{"0", "0.0.0", 0},
	}

	for _, tt := range tests {
		got := compareSemver(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
