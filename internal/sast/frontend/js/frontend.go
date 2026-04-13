package js

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/ir"
)

// ParseFile reads a JS/TS file and returns its SentinelIR module.
func ParseFile(absPath, relPath string) (*ir.Module, error) {
	src, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("js frontend: read %s: %w", absPath, err)
	}
	return Parse(relPath, src), nil
}

// ParseSource parses JS/TS source bytes.
func ParseSource(relPath string, src []byte) *ir.Module {
	return Parse(relPath, src)
}

// WalkJSFiles walks a directory tree and returns every .js, .ts, .jsx, .tsx file.
func WalkJSFiles(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "node_modules", ".git", "dist", "build", ".next", "coverage":
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx" {
			// Skip .d.ts declaration files.
			if strings.HasSuffix(info.Name(), ".d.ts") {
				return nil
			}
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
