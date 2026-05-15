// blobstore.go — minimal object-store abstraction used by the evidence
// export worker.
//
// The interface is intentionally narrow (Put / Get / Delete / Exists) so
// production deployments can plug in a MinIO/S3-backed implementation in a
// follow-up commit without disturbing the worker contract. The reference
// FilesystemBlob writes to a configurable directory and is what
// docker-compose wires up by mounting the MinIO data volume into a shared
// path — same single-binary deployment story as the rest of SentinelCore.

package evidence

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BlobClient is the minimal contract the export worker needs from an object
// store. The keys are slash-separated paths ("org/<org>/exports/<id>.zip").
type BlobClient interface {
	Put(key string, r io.Reader) (size int64, err error)
	Get(key string) (io.ReadCloser, error)
	Delete(key string) error
	Exists(key string) bool
}

// ErrBlobNotFound is returned by BlobClient.Get when the key has no object.
var ErrBlobNotFound = errors.New("blob not found")

// FilesystemBlob is a BlobClient backed by a local directory. Suitable for
// single-host docker-compose deployments where MinIO mounts the same volume.
type FilesystemBlob struct {
	root string
}

// NewFilesystemBlob creates a FilesystemBlob rooted at dir. Returns an error
// if the directory cannot be created.
func NewFilesystemBlob(dir string) (*FilesystemBlob, error) {
	if dir == "" {
		return nil, fmt.Errorf("FilesystemBlob: dir is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("FilesystemBlob: mkdir %s: %w", dir, err)
	}
	return &FilesystemBlob{root: dir}, nil
}

func (f *FilesystemBlob) path(key string) string {
	return filepath.Join(f.root, filepath.FromSlash(key))
}

// Put writes r to disk at key. Parent directories are created on demand.
func (f *FilesystemBlob) Put(key string, r io.Reader) (int64, error) {
	target := f.path(key)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, fmt.Errorf("FilesystemBlob.Put: mkdir: %w", err)
	}
	out, err := os.Create(target)
	if err != nil {
		return 0, fmt.Errorf("FilesystemBlob.Put: create: %w", err)
	}
	defer out.Close()
	n, err := io.Copy(out, r)
	if err != nil {
		_ = os.Remove(target)
		return 0, fmt.Errorf("FilesystemBlob.Put: copy: %w", err)
	}
	return n, nil
}

// Get returns a ReadCloser for the object at key.
func (f *FilesystemBlob) Get(key string) (io.ReadCloser, error) {
	rc, err := os.Open(f.path(key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrBlobNotFound
		}
		return nil, fmt.Errorf("FilesystemBlob.Get: %w", err)
	}
	return rc, nil
}

// Delete removes the object at key. A non-existent key returns nil.
func (f *FilesystemBlob) Delete(key string) error {
	err := os.Remove(f.path(key))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("FilesystemBlob.Delete: %w", err)
	}
	return nil
}

// Exists returns true when the object at key is present and readable.
func (f *FilesystemBlob) Exists(key string) bool {
	_, err := os.Stat(f.path(key))
	return err == nil
}

// Root exposes the underlying directory — used by the API DownloadExport
// handler when it serves the file directly (no presigned URLs in this
// deployment model).
func (f *FilesystemBlob) Root() string { return f.root }
