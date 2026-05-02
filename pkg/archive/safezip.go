// Package archive provides safe ZIP inspection and extraction helpers used by
// the SAST source/artifact intake flow. The validator rejects anything that
// could enable directory traversal, symlink escape, or zip bomb attacks, so
// the controlplane can accept operator uploads without exposing the scan
// worker to classic archive-handling CVEs.
package archive

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Limits constrains the set of sizes a validator will accept.
type Limits struct {
	// MaxCompressedBytes caps the on-disk size of the zip file itself.
	MaxCompressedBytes int64
	// MaxUncompressedBytes caps the total uncompressed size of all entries.
	MaxUncompressedBytes int64
	// MaxEntryBytes caps a single entry's uncompressed size.
	MaxEntryBytes int64
	// MaxEntries caps the number of entries in the archive.
	MaxEntries int
}

// DefaultLimits are the pilot-safe limits: 256 MiB on disk, 1 GiB uncompressed,
// 256 MiB per file, 200k entries. These can be tuned via env later.
func DefaultLimits() Limits {
	return Limits{
		MaxCompressedBytes:   256 * 1024 * 1024,
		MaxUncompressedBytes: 1024 * 1024 * 1024,
		MaxEntryBytes:        256 * 1024 * 1024,
		MaxEntries:           200_000,
	}
}

// Summary is the result of validating a zip file without extracting.
type Summary struct {
	EntryCount       int
	UncompressedSize int64
}

// ErrUnsafeZip is the sentinel for any validation failure. Callers should use
// errors.Is for distinguishing, not string matching.
var ErrUnsafeZip = errors.New("archive: unsafe zip")

// ValidateZipFile opens a zip at path, inspects every entry against Limits,
// and returns a Summary on success. It never extracts anything to disk, so
// it is cheap to run on an untrusted upload before committing it to storage.
func ValidateZipFile(path string, limits Limits) (*Summary, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > limits.MaxCompressedBytes {
		return nil, fmt.Errorf("%w: compressed size %d exceeds limit %d", ErrUnsafeZip, fi.Size(), limits.MaxCompressedBytes)
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsafeZip, err)
	}
	defer zr.Close()

	if len(zr.File) > limits.MaxEntries {
		return nil, fmt.Errorf("%w: %d entries exceeds limit %d", ErrUnsafeZip, len(zr.File), limits.MaxEntries)
	}

	var total int64
	for _, f := range zr.File {
		if err := validateEntry(f, limits); err != nil {
			return nil, err
		}
		total += int64(f.UncompressedSize64)
		if total > limits.MaxUncompressedBytes {
			return nil, fmt.Errorf("%w: total uncompressed size %d exceeds limit %d", ErrUnsafeZip, total, limits.MaxUncompressedBytes)
		}
	}

	return &Summary{
		EntryCount:       len(zr.File),
		UncompressedSize: total,
	}, nil
}

// OpenZipForExtraction opens a validated zip file for reading. Callers should
// call ValidateZipFile first, then use this to iterate entries for extraction.
func OpenZipForExtraction(path string) (*zip.ReadCloser, error) {
	return zip.OpenReader(path)
}

// validateEntry enforces per-entry rules: no absolute paths, no parent
// traversal, no symlinks, no device/special files, size within limit.
func validateEntry(f *zip.File, limits Limits) error {
	name := f.Name

	// archive/zip reports entries in their stored form. We reject anything that
	// contains a backslash (windows path separator), a null byte, or an
	// absolute path marker. We also reject any entry whose cleaned path
	// escapes the logical root.
	if strings.ContainsAny(name, "\x00") {
		return fmt.Errorf("%w: entry name contains null byte", ErrUnsafeZip)
	}
	if strings.Contains(name, "\\") {
		return fmt.Errorf("%w: entry name contains backslash: %q", ErrUnsafeZip, name)
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("%w: absolute path: %q", ErrUnsafeZip, name)
	}
	// filepath.IsAbs catches windows drive letters like C:/
	if filepath.IsAbs(name) {
		return fmt.Errorf("%w: absolute path: %q", ErrUnsafeZip, name)
	}
	// Reject any explicit parent traversal component. We do this component-wise
	// rather than via filepath.Clean because Clean collapses "..": e.g.
	// "../../etc/passwd" becomes "/etc/passwd" after Clean("/" + name), which
	// would sneak past a string-prefix check.
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return fmt.Errorf("%w: path traversal: %q", ErrUnsafeZip, name)
		}
	}
	// Reject symlinks and other non-regular files. Only directories and
	// regular files are allowed.
	mode := f.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symlink entry not allowed: %q", ErrUnsafeZip, name)
	}
	if mode&os.ModeDevice != 0 || mode&os.ModeNamedPipe != 0 || mode&os.ModeSocket != 0 || mode&os.ModeCharDevice != 0 {
		return fmt.Errorf("%w: special file not allowed: %q", ErrUnsafeZip, name)
	}
	// Per-entry uncompressed size.
	if int64(f.UncompressedSize64) > limits.MaxEntryBytes {
		return fmt.Errorf("%w: entry %q uncompressed size %d exceeds limit %d", ErrUnsafeZip, name, f.UncompressedSize64, limits.MaxEntryBytes)
	}
	return nil
}

// LooksLikeZip returns true iff the first 4 bytes of r match the PKZip magic.
// Caller should io.Seek(r,0,0) afterward if they plan to reuse r.
func LooksLikeZip(r io.ReaderAt) bool {
	buf := make([]byte, 4)
	n, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return false
	}
	if n < 4 {
		return false
	}
	return buf[0] == 'P' && buf[1] == 'K' && buf[2] == 0x03 && buf[3] == 0x04
}
