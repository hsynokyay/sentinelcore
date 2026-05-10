package python

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
	"github.com/sentinelcore/sentinelcore/internal/sast/lang"
)

// ParseFile reads a Python file and returns its SentinelIR module.
func ParseFile(absPath, relPath string) (*ir.Module, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("python frontend: read %s: %w", absPath, err)
	}
	return Parse(relPath, src), nil
}

// ParseSource parses Python source bytes.
func ParseSource(relPath string, src []byte) *ir.Module {
	return Parse(relPath, src)
}

// WalkPythonFiles walks a directory tree and returns every .py file,
// skipping __pycache__, .venv, venv, .tox, .eggs, dist, build.
func WalkPythonFiles(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "__pycache__", ".venv", "venv", ".tox", ".eggs", "dist", "build", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		// internal/sast/lang owns the canonical extension→language map; we
		// delegate so that adding a Python dialect (e.g. .pyi) only edits
		// one place rather than every walker.
		if lang.ForExtension(info.Name()) == "python" {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
