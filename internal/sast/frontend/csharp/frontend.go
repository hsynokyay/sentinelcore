package csharp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/lang"
)

// ParseFile reads a .cs file from disk and returns its SentinelIR module.
// absPath is the real filesystem location; relPath is the artifact-relative
// path stored in the module (and contributes to fingerprints).
func ParseFile(absPath, relPath string) (*ir.Module, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("csharp frontend: read %s: %w", absPath, err)
	}
	return Parse(relPath, src), nil
}

// ParseSource parses a C# source byte slice that did not come from disk.
// Useful for tests.
func ParseSource(relPath string, src []byte) *ir.Module {
	return Parse(relPath, src)
}

// WalkCSharpFiles walks the given directory tree and returns every path whose
// name ends in ".cs". The walker deliberately skips standard C# build and
// tooling directories (bin, obj, .vs, .git, node_modules, packages, .nuget)
// which contain either generated code or IDE state, not source we want to
// analyze.
func WalkCSharpFiles(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "bin", "obj", ".git", ".vs", ".idea", "node_modules", "packages", ".nuget":
				return filepath.SkipDir
			}
			return nil
		}
		// internal/sast/lang owns the canonical extension→language map; we
		// delegate so adding a new C# file kind only edits one place. The
		// auto-generated-file exclusions stay here because they're
		// C#-specific refinements, not extension-level detection.
		if lang.ForExtension(info.Name()) == "csharp" {
			if strings.HasSuffix(info.Name(), ".g.cs") || strings.HasSuffix(info.Name(), ".Designer.cs") || strings.HasSuffix(info.Name(), ".AssemblyInfo.cs") {
				return nil
			}
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
