package api

import "testing"

func TestSanitizeDisplayName(t *testing.T) {
	cases := map[string]string{
		"app.zip":                    "app.zip",
		"../../etc/passwd":           "passwd",
		"subdir/app.zip":             "app.zip",
		"  spaced.zip  ":             "spaced.zip",
		"ctrl\x00chars.zip":          "ctrlchars.zip",
		"C:\\path\\app.zip":          "C:\\path\\app.zip", // filepath.Base on unix leaves \ alone; that's fine
		"":                           "",
	}
	for in, want := range cases {
		if got := sanitizeDisplayName(in); got != want {
			t.Errorf("sanitizeDisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}
