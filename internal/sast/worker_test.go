package sast

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzer_DetectsSQLInjection(t *testing.T) {
	// Create temp file with vulnerable Java code
	dir := t.TempDir()
	code := `public class UserService {
    public User findUser(String id) {
        return db.executeQuery("SELECT * FROM users WHERE id=" + id);
    }
}`
	err := os.WriteFile(filepath.Join(dir, "UserService.java"), []byte(code), 0644)
	if err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRules("../../rules/builtin/sast-patterns.json")
	if err != nil {
		t.Fatal(err)
	}

	analyzer := NewAnalyzer(rules)
	findings, err := analyzer.AnalyzeDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one SQL injection finding")
	}

	found := false
	for _, f := range findings {
		if f.CWEID == 89 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CWE-89 (SQL Injection) finding")
	}
}

func TestAnalyzer_DetectsHardcodedSecret(t *testing.T) {
	dir := t.TempDir()
	code := `password = "SuperSecretP@ssw0rd123"`
	os.WriteFile(filepath.Join(dir, "config.py"), []byte(code), 0644)

	rules, _ := LoadRules("../../rules/builtin/sast-patterns.json")
	analyzer := NewAnalyzer(rules)
	findings, _ := analyzer.AnalyzeDirectory(dir)

	found := false
	for _, f := range findings {
		if f.CWEID == 798 {
			found = true
		}
	}
	if !found {
		t.Error("expected CWE-798 (Hardcoded Secret) finding")
	}
}

func TestAnalyzer_SkipsUnsupportedFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not code"), 0644)

	rules, _ := LoadRules("../../rules/builtin/sast-patterns.json")
	analyzer := NewAnalyzer(rules)
	findings, _ := analyzer.AnalyzeDirectory(dir)

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-code file, got %d", len(findings))
	}
}
