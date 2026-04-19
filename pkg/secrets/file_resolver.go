package secrets

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// FileResolver reads secrets from a single key=value file. Used in
// docker-compose dev setups where binding 30+ env vars is awkward.
//
// File format:
//
//   tier0/aes/master=<base64>
//   tier1/postgres/controlplane=<password>
//   # comments with # are ignored
//   # blank lines too
//
// Permissions: the file MUST be mode 0600. FileResolver refuses to
// read anything else — a world-readable secret file is a silent data
// leak. Operators enforce mode via `chmod 600 secrets.local`; CI sets
// it via `umask 077`.
type FileResolver struct {
	path  string
	store map[string]string
}

// NewFileResolver loads the whole file into memory at startup. Rotation
// = edit the file + restart the process; no hot reload (any reload
// path is a source of TOCTOU bugs).
func NewFileResolver(path string) (*FileResolver, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("secrets.file: stat %s: %w", path, err)
	}
	// Refuse any perms wider than 0600. Owner read-write only.
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"secrets.file: %s has mode %v; must be 0600",
			path, st.Mode().Perm())
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("secrets.file: open: %w", err)
	}
	defer f.Close()

	store := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1024*1024) // allow big b64 blobs
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("secrets.file: %s:%d missing '='",
				path, line)
		}
		store[raw[:eq]] = raw[eq+1:]
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("secrets.file: scan: %w", err)
	}
	return &FileResolver{path: path, store: store}, nil
}

func (*FileResolver) Backend() string { return "file" }

func (r *FileResolver) Get(ctx context.Context, path string) ([]byte, error) {
	v, ok := r.store[path]
	if !ok {
		return nil, fmt.Errorf("%w: %s (file %s)", ErrNotFound, path, r.path)
	}
	return []byte(v), nil
}

func (r *FileResolver) GetString(ctx context.Context, path string) (string, error) {
	v, ok := r.store[path]
	if !ok {
		return "", fmt.Errorf("%w: %s (file %s)", ErrNotFound, path, r.path)
	}
	return v, nil
}

func (r *FileResolver) Version(ctx context.Context, path string) (int, error) {
	if _, ok := r.store[path]; !ok {
		return -1, fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	return -1, nil
}
