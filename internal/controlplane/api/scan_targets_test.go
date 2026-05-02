package api

import "testing"

func TestValidateTargetRequest(t *testing.T) {
	cases := []struct {
		name    string
		req     scanTargetRequest
		wantErr bool
		check   func(t *testing.T, out scanTargetRequest)
	}{
		{
			name: "web_app minimal defaults",
			req: scanTargetRequest{
				TargetType: "web_app",
				BaseURL:    "https://demo.example.com/api",
			},
			check: func(t *testing.T, out scanTargetRequest) {
				if len(out.AllowedDomains) != 1 || out.AllowedDomains[0] != "demo.example.com" {
					t.Errorf("allowed_domains default: %v", out.AllowedDomains)
				}
				if out.MaxRPS == nil || *out.MaxRPS != 10 {
					t.Errorf("max_rps default: %v", out.MaxRPS)
				}
				if len(out.AllowedPorts) != 2 {
					t.Errorf("allowed_ports default: %v", out.AllowedPorts)
				}
				if out.Label == "" {
					t.Error("label should default to host")
				}
			},
		},
		{
			name:    "rejects missing scheme",
			req:     scanTargetRequest{TargetType: "api", BaseURL: "demo.example.com"},
			wantErr: true,
		},
		{
			name:    "rejects ftp scheme",
			req:     scanTargetRequest{TargetType: "api", BaseURL: "ftp://files.example.com"},
			wantErr: true,
		},
		{
			name:    "rejects unknown target_type",
			req:     scanTargetRequest{TargetType: "desktop", BaseURL: "https://example.com"},
			wantErr: true,
		},
		{
			name: "max_rps out of range",
			req: scanTargetRequest{
				TargetType: "web_app",
				BaseURL:    "https://example.com",
				MaxRPS:     intPtr(9999),
			},
			wantErr: true,
		},
		{
			name: "honours explicit allowed_domains and lowercases",
			req: scanTargetRequest{
				TargetType:     "web_app",
				BaseURL:        "https://example.com",
				AllowedDomains: []string{"Example.COM", "api.example.com"},
			},
			check: func(t *testing.T, out scanTargetRequest) {
				if out.AllowedDomains[0] != "example.com" || out.AllowedDomains[1] != "api.example.com" {
					t.Errorf("allowed_domains not normalized: %v", out.AllowedDomains)
				}
			},
		},
		{
			name: "rejects out-of-range port",
			req: scanTargetRequest{
				TargetType:   "api",
				BaseURL:      "https://example.com",
				AllowedPorts: []int32{70000},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, errMsg := validateTargetRequest(&tc.req)
			if tc.wantErr && errMsg == "" {
				t.Fatalf("expected validation error, got none; out=%+v", out)
			}
			if !tc.wantErr && errMsg != "" {
				t.Fatalf("unexpected error: %s", errMsg)
			}
			if tc.check != nil && errMsg == "" {
				tc.check(t, out)
			}
		})
	}
}

func intPtr(n int) *int { return &n }
