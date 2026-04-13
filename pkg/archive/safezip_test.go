package archive

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// makeZip builds a zip file at path from the given entries.
type zipEntry struct {
	name    string
	content []byte
	mode    os.FileMode
}

func makeZip(t *testing.T, path string, entries []zipEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	for _, e := range entries {
		header := &zip.FileHeader{
			Name:   e.name,
			Method: zip.Deflate,
		}
		if e.mode != 0 {
			header.SetMode(e.mode)
		}
		fw, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if len(e.content) > 0 {
			if _, err := fw.Write(e.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateZipFileHappyPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ok.zip")
	makeZip(t, p, []zipEntry{
		{name: "src/main.go", content: []byte("package main\nfunc main(){}\n")},
		{name: "src/lib/util.go", content: []byte("package lib\n")},
		{name: "README.md", content: []byte("# hello\n")},
	})

	s, err := ValidateZipFile(p, DefaultLimits())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if s.EntryCount != 3 {
		t.Errorf("entry count = %d, want 3", s.EntryCount)
	}
	if s.UncompressedSize == 0 {
		t.Error("uncompressed size should be > 0")
	}
}

func TestValidateZipRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.zip")
	makeZip(t, p, []zipEntry{
		{name: "../../etc/passwd", content: []byte("x")},
	})
	_, err := ValidateZipFile(p, DefaultLimits())
	if !errors.Is(err, ErrUnsafeZip) {
		t.Fatalf("expected ErrUnsafeZip, got %v", err)
	}
}

func TestValidateZipRejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.zip")
	makeZip(t, p, []zipEntry{
		{name: "/etc/passwd", content: []byte("x")},
	})
	_, err := ValidateZipFile(p, DefaultLimits())
	if !errors.Is(err, ErrUnsafeZip) {
		t.Fatalf("expected ErrUnsafeZip, got %v", err)
	}
}

func TestValidateZipRejectsBackslash(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.zip")
	makeZip(t, p, []zipEntry{
		{name: "src\\evil.txt", content: []byte("x")},
	})
	_, err := ValidateZipFile(p, DefaultLimits())
	if !errors.Is(err, ErrUnsafeZip) {
		t.Fatalf("expected ErrUnsafeZip, got %v", err)
	}
}

func TestValidateZipRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.zip")
	// Build a zip containing a symlink entry directly.
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	h := &zip.FileHeader{Name: "link"}
	h.SetMode(os.ModeSymlink | 0o777)
	fw, _ := w.CreateHeader(h)
	fw.Write([]byte("/etc/shadow"))
	w.Close()
	f.Close()

	_, err = ValidateZipFile(p, DefaultLimits())
	if !errors.Is(err, ErrUnsafeZip) {
		t.Fatalf("expected ErrUnsafeZip, got %v", err)
	}
}

func TestValidateZipTotalSizeLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.zip")
	// Tiny per-entry, but many entries pushing the total over the limit.
	big := bytes.Repeat([]byte("A"), 1024)
	entries := make([]zipEntry, 0, 50)
	for i := 0; i < 50; i++ {
		entries = append(entries, zipEntry{name: "f" + string(rune('a'+i)) + ".txt", content: big})
	}
	makeZip(t, p, entries)

	// Set a tiny total limit so we trip it.
	tight := DefaultLimits()
	tight.MaxUncompressedBytes = 10 * 1024
	_, err := ValidateZipFile(p, tight)
	if !errors.Is(err, ErrUnsafeZip) {
		t.Fatalf("expected ErrUnsafeZip, got %v", err)
	}
}

func TestValidateZipEntryCountLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "many.zip")
	entries := make([]zipEntry, 0, 5)
	for i := 0; i < 5; i++ {
		entries = append(entries, zipEntry{name: "f" + string(rune('a'+i)) + ".txt", content: []byte("x")})
	}
	makeZip(t, p, entries)

	tight := DefaultLimits()
	tight.MaxEntries = 3
	_, err := ValidateZipFile(p, tight)
	if !errors.Is(err, ErrUnsafeZip) {
		t.Fatalf("expected ErrUnsafeZip, got %v", err)
	}
}

func TestLooksLikeZip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ok.zip")
	makeZip(t, p, []zipEntry{{name: "a.txt", content: []byte("a")}})

	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !LooksLikeZip(f) {
		t.Error("expected LooksLikeZip(true)")
	}

	bad := filepath.Join(dir, "not.zip")
	os.WriteFile(bad, []byte("this is not a zip"), 0o644)
	bf, _ := os.Open(bad)
	defer bf.Close()
	if LooksLikeZip(bf) {
		t.Error("expected LooksLikeZip(false)")
	}
}
