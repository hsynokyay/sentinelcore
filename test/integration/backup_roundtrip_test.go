package integration

// backup_roundtrip_test.go — end-to-end exercise of cmd/backup.
//
// Writes a dump, decrypts it with age, and asserts that the plaintext
// head looks like a pg_dump custom-format archive ("PGDMP" magic).
// Stops short of restoring into a throwaway DB — that's the operator's
// validation step in the runbook, and running it here would require
// spinning up a second Postgres which the test harness doesn't do.
//
// Skips unless:
//   - TEST_DATABASE_URL is set, AND
//   - `pg_dump` is on PATH, AND
//   - `age` and `age-keygen` are on PATH.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func needBin(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not on PATH", name)
	}
}

func TestBackupRoundtrip(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	needBin(t, "pg_dump")
	needBin(t, "age")
	needBin(t, "age-keygen")

	// Build the sc-backup binary into a temp dir.
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "sc-backup")
	buildCmd := exec.Command("go", "build", "-o", bin, "../../cmd/backup")
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("go build cmd/backup: %v", err)
	}

	// Generate an age keypair for this run.
	keyPath := filepath.Join(tmp, "key.txt")
	kg := exec.Command("age-keygen", "-o", keyPath)
	kg.Stderr = os.Stderr
	if err := kg.Run(); err != nil {
		t.Fatalf("age-keygen: %v", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := extractPublicKey(string(keyBytes))
	if pub == "" {
		t.Fatalf("no public key in age keyfile:\n%s", keyBytes)
	}

	// Run sc-backup.
	outPath := filepath.Join(tmp, "dump.sql.age")
	bg := exec.Command(bin,
		"--out", outPath,
		"--recipient", pub,
		"--db-url", dsn)
	bg.Stdout = os.Stdout
	bg.Stderr = os.Stderr
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bg = exec.CommandContext(ctx, bg.Path, bg.Args[1:]...)
	bg.Stderr = os.Stderr
	if err := bg.Run(); err != nil {
		t.Fatalf("sc-backup: %v", err)
	}

	// File exists and is nonzero.
	fi, err := os.Stat(outPath)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("output missing or empty: %v (size=%d)", err, fi.Size())
	}

	// Decrypt with age and check the first bytes look like pg_dump.
	dec := exec.Command("age", "--decrypt", "-i", keyPath, outPath)
	var out bytes.Buffer
	dec.Stdout = &out
	dec.Stderr = os.Stderr
	if err := dec.Run(); err != nil {
		t.Fatalf("age --decrypt: %v", err)
	}

	head := out.Bytes()
	if len(head) < 16 {
		t.Fatalf("decrypted output too short: %d bytes", len(head))
	}
	// pg_dump --format=custom magic: "PGDMP"
	if !bytes.HasPrefix(head, []byte("PGDMP")) {
		t.Errorf("decrypted output doesn't start with PGDMP magic; got %q", head[:16])
	}
}

// extractPublicKey pulls the "public key:" line out of `age-keygen`
// output format:
//
//   # created: 2026-04-19T13:31:00Z
//   # public key: age1abcdef...
//   AGE-SECRET-KEY-1...
func extractPublicKey(s string) string {
	for _, line := range strings.Split(s, "\n") {
		const prefix = "# public key: "
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}
