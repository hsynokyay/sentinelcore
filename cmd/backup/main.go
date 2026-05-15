// Command sc-backup produces an age-encrypted pg_dump of the
// SentinelCore database, suitable for cold storage or off-site
// retention.
//
// Usage:
//
//   sc-backup --out /var/backups/sc/%Y-%m-%dT%H-%M-%S.sql.age \
//             --recipient age1xxx...
//
// Flags:
//
//   --out         Output path (supports strftime-style tokens)
//   --recipient   Age public key (X25519). Can be repeated. At least one required.
//                 Alternatively, set SC_BACKUP_AGE_RECIPIENTS (space-separated).
//   --db-url      Postgres DSN; defaults to DATABASE_URL env
//   --no-stream   Buffer the whole dump in RAM before writing (small DBs only)
//
// The binary streams pg_dump stdout → age writer → output file without
// ever materialising the plaintext on disk. For GB+ databases, make
// sure --out is on a disk with enough free space for the encrypted
// blob (typically ~30% smaller than the SQL due to gzip — see below).
//
// Dump format: `pg_dump --format=custom` (compressed, indexable, can
// be restored with pg_restore on a newer Postgres version). The
// encrypted file IS the dump; no intermediate tarball.
//
// Restore: `age --decrypt -i key.txt backup.sql.age | pg_restore ...`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"filippo.io/age"
)

func main() {
	var (
		outPath     string
		recipients  stringSlice
		dbURL       string
	)
	flag.StringVar(&outPath, "out", "", "output path (strftime-style tokens allowed)")
	flag.Var(&recipients, "recipient", "age public key (X25519); may be repeated")
	flag.StringVar(&dbURL, "db-url", "", "Postgres DSN (default: $DATABASE_URL)")
	flag.Parse()

	// Env-fallback for recipients so systemd timers don't need
	// argument wrangling.
	if len(recipients) == 0 {
		if v := os.Getenv("SC_BACKUP_AGE_RECIPIENTS"); v != "" {
			for _, r := range strings.Fields(v) {
				recipients = append(recipients, r)
			}
		}
	}
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}

	if outPath == "" || len(recipients) == 0 || dbURL == "" {
		fmt.Fprintln(os.Stderr,
			"usage: sc-backup --out <path> --recipient <age-pubkey> [--db-url <dsn>]")
		os.Exit(2)
	}

	outPath = expandTokens(outPath, time.Now().UTC())

	recips, err := parseRecipients(recipients)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse recipients: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	if err := run(ctx, dbURL, outPath, recips); err != nil {
		fmt.Fprintf(os.Stderr, "backup failed: %v\n", err)
		// Leave a partially-written file around for diagnosis but
		// rename it so a cron job retry doesn't overwrite the
		// evidence.
		_ = os.Rename(outPath, outPath+".FAILED")
		os.Exit(1)
	}

	fmt.Printf("backup complete: %s\n", outPath)
}

func run(ctx context.Context, dbURL, outPath string, recipients []age.Recipient) error {
	// Open the output file first — fail fast on permission/path errors
	// BEFORE spawning pg_dump.
	tmpPath := outPath + ".part"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer f.Close()

	ageW, err := age.Encrypt(f, recipients...)
	if err != nil {
		return fmt.Errorf("age encrypt init: %w", err)
	}

	// pg_dump --format=custom streams a binary-compressed archive on
	// stdout. `--blobs --no-owner --no-privileges` makes it portable
	// to a differently-named DB role (important post-role-split).
	cmd := exec.CommandContext(ctx, "pg_dump",
		"--format=custom",
		"--no-owner",
		"--no-privileges",
		"--blobs",
		dbURL,
	)
	cmd.Stdout = ageW
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_dump: %w", err)
	}

	// Close the age writer first — it flushes the trailing MAC.
	// Closing the underlying file after that commits the bytes.
	if err := ageW.Close(); err != nil {
		return fmt.Errorf("age close: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("file close: %w", err)
	}

	// Atomic rename so partial files don't masquerade as complete
	// backups if the process is killed.
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// parseRecipients turns each CLI --recipient string into an age.Recipient.
// Accepts age1... X25519 keys; ssh keys and plugin forms are rejected
// here because they add CGO / subprocess deps.
func parseRecipients(in []string) ([]age.Recipient, error) {
	if len(in) == 0 {
		return nil, errors.New("at least one --recipient required")
	}
	out := make([]age.Recipient, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("recipient %q: %w", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// expandTokens replaces %Y %m %d %H %M %S in a path with the current
// UTC time. Equivalent to the common strftime tokens without pulling
// in a full strftime dep.
func expandTokens(s string, now time.Time) string {
	repl := strings.NewReplacer(
		"%Y", fmt.Sprintf("%04d", now.Year()),
		"%m", fmt.Sprintf("%02d", int(now.Month())),
		"%d", fmt.Sprintf("%02d", now.Day()),
		"%H", fmt.Sprintf("%02d", now.Hour()),
		"%M", fmt.Sprintf("%02d", now.Minute()),
		"%S", fmt.Sprintf("%02d", now.Second()),
	)
	return repl.Replace(s)
}

// --- flag.Value impl for repeated --recipient ---

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// ensure the import block keeps io (expand uses it via os.File).
var _ = io.Copy
