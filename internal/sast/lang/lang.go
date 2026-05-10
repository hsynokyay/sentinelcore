// Package lang owns the canonical "file extension → language" map used
// across the SAST stack. It is a deliberately small, leaf package so that
// both the per-language frontend walkers and the engine's rule router can
// depend on it without creating an import cycle.
//
// Before this package existed, every per-language walker
// (`internal/sast/frontend/{java,python,js,csharp}/frontend.go`) hardcoded
// its own extension list, which meant adding a new language required
// editing every walker plus the engine. Now there is one map.
//
// Canonical language names match the values produced by the alias
// normalization in `internal/sast/rules/loader.go` (typescript collapses
// to "javascript", and so on) and the `ir.Module.Language` field. To add
// a language: add the extension(s) here AND, if the language has variants,
// add an alias entry in `rules/loader.go`. Walkers only need new entries
// here — they do not need editing unless a brand new walker is being
// introduced for a new parser.
package lang

import (
	"path/filepath"
	"strings"
)

// extensionToLanguage maps a lowercased file extension (with the leading
// dot) to the canonical language name. Order doesn't matter; lookups are
// O(1).
var extensionToLanguage = map[string]string{
	".java": "java",
	".py":   "python",
	".js":   "javascript",
	".mjs":  "javascript",
	".cjs":  "javascript",
	".jsx":  "javascript",
	".ts":   "javascript",
	".tsx":  "javascript",
	".cs":   "csharp",
}

// ForExtension returns the canonical language name for the given file
// path's extension, or "" if the extension is unknown. The path may be a
// bare filename, a relative path, or absolute — only the trailing
// extension is consulted, lowercased.
//
// Returns "" rather than an error so callers can use it inline:
//
//	if lang.ForExtension(path) == "java" { … }
//
// without needing to thread errors through walker callbacks.
func ForExtension(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	return extensionToLanguage[ext]
}
