package risk

import "testing"

func TestNormalizeRoute(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain path", "/users", "/users"},
		{"lowercase", "/Users/Foo", "/users/foo"},
		{"strip scheme host", "https://api.example.com/users", "/users"},
		{"strip query", "/users?id=1&filter=x", "/users"},
		{"strip trailing slash", "/users/", "/users"},
		{"preserve root", "/", "/"},
		{"numeric segment", "/users/42", "/users/:num"},
		{"uuid segment", "/users/550e8400-e29b-41d4-a716-446655440000", "/users/:uuid"},
		{"long alnum token", "/download/abc123DEF456ghi789jkl", "/download/:token"},
		{"short literal preserved", "/users/admin", "/users/admin"},
		{"positional params", "/users/1/orders/2", "/users/:num/orders/:num"},
		{"url-decoded", "/users/john%20doe", "/users/john doe"},
		{"mixed case host stripped", "https://API.example.com:8443/Users/", "/users"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NormalizeRoute(c.in)
			if got != c.want {
				t.Errorf("NormalizeRoute(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeParam(t *testing.T) {
	cases := map[string]string{
		"":       "",
		"UserID": "userid",
		"  id  ": "id",
		"X-Auth": "x-auth",
	}
	for in, want := range cases {
		if got := NormalizeParam(in); got != want {
			t.Errorf("NormalizeParam(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeFilePath(t *testing.T) {
	cases := map[string]string{
		"src/Foo.java":   "src/Foo.java",
		"./src/Foo.java": "src/Foo.java",
		`src\Foo.java`:   "src/Foo.java",
		`.\src\Foo.java`: "src/Foo.java",
	}
	for in, want := range cases {
		if got := NormalizeFilePath(in); got != want {
			t.Errorf("NormalizeFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLocationGroup_PrefersMethod(t *testing.T) {
	got := LocationGroup("findUser", 42, 89)
	want := "m:findUser"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLocationGroup_BucketFallback(t *testing.T) {
	cases := []struct {
		function string
		line     int
		cwe      int
		want     string
	}{
		{"", 0, 89, "b:0:cwe_89"},
		{"", 24, 89, "b:0:cwe_89"},
		{"", 25, 89, "b:1:cwe_89"},
		{"", 200, 22, "b:8:cwe_22"},
		{"   ", 75, 89, "b:3:cwe_89"}, // whitespace-only treated as empty
	}
	for _, c := range cases {
		got := LocationGroup(c.function, c.line, c.cwe)
		if got != c.want {
			t.Errorf("LocationGroup(%q, %d, %d) = %q, want %q",
				c.function, c.line, c.cwe, got, c.want)
		}
	}
}

func TestComputeFingerprint_DAST(t *testing.T) {
	f := &Finding{
		Type:       "dast",
		ProjectID:  "proj-1",
		CWEID:      89,
		HTTPMethod: "POST",
		URL:        "https://api.example.com/api/users/42",
		Parameter:  "ID",
	}
	fp, kind, version := ComputeFingerprint(f)
	if kind != "dast_route" {
		t.Errorf("kind = %q, want dast_route", kind)
	}
	if version != FingerprintVersion {
		t.Errorf("version = %d, want %d", version, FingerprintVersion)
	}
	if fp == "" || len(fp) != 64 {
		t.Errorf("fingerprint = %q, want 64-char hex", fp)
	}

	// Deterministic: same input → same fingerprint.
	fp2, _, _ := ComputeFingerprint(f)
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %q vs %q", fp, fp2)
	}

	// Different method → different fingerprint.
	f.HTTPMethod = "GET"
	fp3, _, _ := ComputeFingerprint(f)
	if fp == fp3 {
		t.Error("GET and POST on same route produced same fingerprint")
	}
}

func TestComputeFingerprint_SAST(t *testing.T) {
	f := &Finding{
		Type:         "sast",
		ProjectID:    "proj-1",
		CWEID:        89,
		Language:     "java",
		FilePath:     "src/main/UserRepo.java",
		LineStart:    42,
		FunctionName: "findUser",
	}
	fp, kind, _ := ComputeFingerprint(f)
	if kind != "sast_file" {
		t.Errorf("kind = %q, want sast_file", kind)
	}
	if fp == "" {
		t.Error("empty fingerprint")
	}

	// Different method → different fingerprint.
	f.FunctionName = "updateUser"
	fp2, _, _ := ComputeFingerprint(f)
	if fp == fp2 {
		t.Error("different methods in same file produced same fingerprint")
	}

	// No method → fallback bucket form.
	f.FunctionName = ""
	f.LineStart = 10
	fpBucket, _, _ := ComputeFingerprint(f)
	f.LineStart = 20
	fpBucket2, _, _ := ComputeFingerprint(f)
	if fpBucket != fpBucket2 {
		t.Error("lines 10 and 20 (same bucket) produced different fingerprints")
	}
	f.LineStart = 30
	fpBucket3, _, _ := ComputeFingerprint(f)
	if fpBucket == fpBucket3 {
		t.Error("lines 20 and 30 (different buckets) produced same fingerprint")
	}
}

func TestComputeFingerprint_PolyglotProject(t *testing.T) {
	base := Finding{
		Type:      "sast",
		ProjectID: "proj-1",
		CWEID:     89,
		FilePath:  "src/db.ext",
		LineStart: 10,
	}
	java := base
	java.Language = "java"
	python := base
	python.Language = "python"

	fpJava, _, _ := ComputeFingerprint(&java)
	fpPython, _, _ := ComputeFingerprint(&python)
	if fpJava == fpPython {
		t.Error("polyglot project fingerprints collided across languages")
	}
}
