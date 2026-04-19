package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPathToEnvVar(t *testing.T) {
	cases := map[string]string{
		"tier0/aes/master":           "SC_TIER0_AES_MASTER",
		"tier1/postgres/controlplane": "SC_TIER1_POSTGRES_CONTROLPLANE",
		"tier0/hmac/audit":           "SC_TIER0_HMAC_AUDIT",
	}
	for path, want := range cases {
		got, err := pathToEnvVar(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got != want {
			t.Errorf("%s → %s, want %s", path, got, want)
		}
	}

	// Illegal characters rejected.
	bad := []string{"tier0/../etc/passwd", "tier0 with space", "tier0/FOO"}
	for _, p := range bad {
		if _, err := pathToEnvVar(p); err == nil {
			t.Errorf("expected error for %q", p)
		}
	}
}

func TestEnvResolver_Happy(t *testing.T) {
	t.Setenv("SC_TIER0_AES_MASTER", "hunter2")
	r := NewEnvResolver()
	if got, err := r.GetString(context.Background(), "tier0/aes/master"); err != nil || got != "hunter2" {
		t.Errorf("GetString: got %q err %v", got, err)
	}
	if r.Backend() != "env" {
		t.Errorf("Backend() = %q", r.Backend())
	}
}

func TestEnvResolver_Missing(t *testing.T) {
	r := NewEnvResolver()
	_, err := r.Get(context.Background(), "tier1/postgres/this-does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestFileResolver_Happy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.local")
	if err := os.WriteFile(path, []byte(`
# demo file
tier0/aes/master=abc
tier1/smtp/password=hunter2
`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewFileResolver(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := r.GetString(context.Background(), "tier0/aes/master"); got != "abc" {
		t.Errorf("master: got %q", got)
	}
	if got, _ := r.GetString(context.Background(), "tier1/smtp/password"); got != "hunter2" {
		t.Errorf("smtp: got %q", got)
	}
}

func TestFileResolver_RejectsWideOpenPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.local")
	if err := os.WriteFile(path, []byte("tier0/aes/master=abc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileResolver(path); err == nil {
		t.Fatal("expected error for mode 0644")
	}
}

func TestCachedResolver_ReturnsDefensiveCopy(t *testing.T) {
	t.Setenv("SC_TIER0_AES_MASTER", "abc")
	c := NewCachedResolver(NewEnvResolver(), 30)
	b1, _ := c.Get(context.Background(), "tier0/aes/master")
	b1[0] = 'X'
	b2, _ := c.Get(context.Background(), "tier0/aes/master")
	if b2[0] == 'X' {
		t.Fatal("cache mutated by caller")
	}
}

func TestAllPaths_NoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range AllPaths() {
		if seen[p] {
			t.Errorf("duplicate path %q", p)
		}
		seen[p] = true
	}
}
