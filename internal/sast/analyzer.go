package sast

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinelcore/sentinelcore/pkg/crypto"
)

// Finding represents a single security issue detected during analysis.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CWEID       int    `json:"cwe_id"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	FilePath    string `json:"file_path"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end"`
	CodeSnippet string `json:"code_snippet"`
	Fingerprint string `json:"fingerprint"`
}

// langExtensions maps file extensions to language names.
var langExtensions = map[string]string{
	".java": "java",
	".py":   "python",
	".js":   "javascript",
	".ts":   "javascript",
	".jsx":  "javascript",
	".tsx":  "javascript",
}

// DetectLanguage returns the language name for the given file path based on extension.
func DetectLanguage(filePath string) string {
	ext := filepath.Ext(filePath)
	if lang, ok := langExtensions[ext]; ok {
		return lang
	}
	return ""
}

// Analyzer runs SAST rules against source files.
type Analyzer struct {
	rules []Rule
}

// NewAnalyzer creates an Analyzer with the given compiled rules.
func NewAnalyzer(rules []Rule) *Analyzer {
	return &Analyzer{rules: rules}
}

// AnalyzeFile scans a single file against all applicable rules.
func (a *Analyzer) AnalyzeFile(filePath, relPath string) ([]Finding, error) {
	lang := DetectLanguage(filePath)
	if lang == "" {
		return nil, nil // unsupported language
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	var findings []Finding
	for _, rule := range a.rules {
		if !rule.MatchesLanguage(lang) {
			continue
		}
		for i, line := range lines {
			if rule.compiled.MatchString(line) {
				// Get code snippet (3 lines context)
				start := max(0, i-1)
				end := min(len(lines), i+2)
				snippet := strings.Join(lines[start:end], "\n")

				fp := crypto.HashBytes([]byte(relPath + ":" + fmt.Sprint(i+1) + ":" + rule.ID))

				findings = append(findings, Finding{
					RuleID:      rule.ID,
					Title:       rule.Title,
					Description: rule.Title + " detected in " + relPath,
					CWEID:       rule.CWEID,
					Severity:    rule.Severity,
					Confidence:  rule.Confidence,
					FilePath:    relPath,
					LineStart:   i + 1,
					LineEnd:     i + 1,
					CodeSnippet: snippet,
					Fingerprint: fp,
				})
			}
		}
	}
	return findings, nil
}

// AnalyzeDirectory walks a directory and analyzes all supported files.
func (a *Analyzer) AnalyzeDirectory(rootDir string) ([]Finding, error) {
	var allFindings []Finding
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		// Skip common non-source directories
		rel, _ := filepath.Rel(rootDir, path)
		if shouldSkip(rel) {
			return nil
		}
		findings, err := a.AnalyzeFile(path, rel)
		if err != nil {
			return nil // skip files that can't be read
		}
		allFindings = append(allFindings, findings...)
		return nil
	})
	return allFindings, err
}

func shouldSkip(path string) bool {
	skipDirs := []string{"node_modules", ".git", "vendor", "__pycache__", ".venv", "target", "build", "dist"}
	for _, d := range skipDirs {
		if strings.HasPrefix(path, d+"/") || path == d {
			return true
		}
	}
	return false
}
