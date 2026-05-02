package auth

import "testing"

func TestValidatePasswordComplexity(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
		errMsg   string
	}{
		{"valid", "SecurePass1!xy", false, ""},
		{"valid complex", "C0mpl3x!P@ssw0rd", false, ""},
		{"valid minimum length", "Abcdefghij1!", false, ""},
		{"too short", "Short1!", true, "at least 12 characters"},
		{"no uppercase", "alllowercase1!", true, "uppercase letter"},
		{"no lowercase", "ALLUPPERCASE1!", true, "lowercase letter"},
		{"no digit", "NoDigitsHere!!", true, "digit"},
		{"no special", "NoSpecialChar1x", true, "special character"},
		{"empty", "", true, "at least 12 characters"},
		{"only spaces", "            ", true, "uppercase letter"},
		{"unicode valid", "Pässwörd1!xyzä", false, ""},
		{"just barely valid", "Aa1!aaaaaaaa", false, ""},
		{"11 chars", "Aa1!aaaaaaa", true, "at least 12 characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordComplexity(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordComplexity(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" {
				if got := err.Error(); !contains(got, tt.errMsg) {
					t.Errorf("error message %q should contain %q", got, tt.errMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
