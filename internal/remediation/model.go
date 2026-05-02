// Package remediation provides deterministic, rule-backed remediation
// guidance for SentinelCore findings. Every supported rule has a structured
// remediation pack that explains what is wrong, why it matters, how to fix
// it, and what safe code looks like. The content is embedded in the binary
// and served from the finding detail API — it is never generated at runtime.
//
// This is the SentinelCore equivalent of Fortify's "Recommendations" pane or
// Checkmarx's "Best Fix Location" guidance, but structured as first-class
// product data rather than bolt-on text.
package remediation

import (
	"embed"
	"encoding/json"
	"io/fs"
	"strings"
)

//go:embed packs/*.json
var packsFS embed.FS

// Pack is the remediation metadata for a single rule. Every field is
// deterministic, reviewable, and safe for enterprise screenshots and audits.
type Pack struct {
	RuleID    string `json:"rule_id"`
	Version   string `json:"version"`
	Title     string `json:"title"`
	Summary   string `json:"summary"`

	// Structured guidance sections.
	WhyItMatters string `json:"why_it_matters"`
	HowToFix     string `json:"how_to_fix"`
	UnsafeExample string `json:"unsafe_example"`
	SafeExample   string `json:"safe_example"`
	DeveloperNotes string `json:"developer_notes,omitempty"`

	// Verification checklist — concise, actionable items a reviewer checks
	// after the developer applies the fix.
	VerificationChecklist []string `json:"verification_checklist"`

	// References — CWE, OWASP, cheat sheets. Each entry is a title or URL.
	References []Reference `json:"references"`
}

// Reference is a single external reference link.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Registry holds all loaded remediation packs keyed by rule_id.
type Registry struct {
	packs map[string]*Pack
}

// LoadBuiltinRegistry loads all embedded remediation packs.
func LoadBuiltinRegistry() (*Registry, error) {
	r := &Registry{packs: map[string]*Pack{}}
	err := fs.WalkDir(packsFS, "packs", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, rErr := fs.ReadFile(packsFS, path)
		if rErr != nil {
			return rErr
		}
		var pack Pack
		if jErr := json.Unmarshal(data, &pack); jErr != nil {
			return jErr
		}
		if pack.RuleID != "" {
			r.packs[pack.RuleID] = &pack
		}
		return nil
	})
	return r, err
}

// Get returns the remediation pack for a rule, or nil if none exists.
func (r *Registry) Get(ruleID string) *Pack {
	if r == nil {
		return nil
	}
	return r.packs[ruleID]
}

// Count returns the number of loaded packs.
func (r *Registry) Count() int {
	if r == nil {
		return 0
	}
	return len(r.packs)
}
