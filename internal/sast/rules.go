package sast

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Rule represents a single SAST detection pattern.
type Rule struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	CWEID      int      `json:"cwe_id"`
	Severity   string   `json:"severity"`
	Confidence string   `json:"confidence"`
	Languages  []string `json:"languages"`
	Pattern    string   `json:"pattern"`
	compiled   *regexp.Regexp
}

// LoadRules reads and compiles SAST rules from a JSON file.
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	for i := range rules {
		rules[i].compiled, err = regexp.Compile(rules[i].Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %s: invalid pattern: %w", rules[i].ID, err)
		}
	}
	return rules, nil
}

// MatchesLanguage returns true if the rule applies to the given language.
func (r *Rule) MatchesLanguage(lang string) bool {
	for _, l := range r.Languages {
		if l == lang {
			return true
		}
	}
	return false
}
