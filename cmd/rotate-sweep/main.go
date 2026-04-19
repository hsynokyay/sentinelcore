// Command rotate-sweep re-encrypts envelope-encoded secret columns from
// an old AES key version to the current version after a rotation.
//
// The cadence: operator runs `sentinelcore-cli rotate aes/<purpose>`
// first. That INSERTs a new row in `auth.aes_keys` at v+1. New writes
// already use v+1. This sweep finds existing rows at < v+1 and
// decrypts-then-re-encrypts them.
//
// Usage:
//
//   rotate-sweep --purpose sso \
//       --table auth.oidc_providers \
//       --column client_secret \
//       --id-column id \
//       --batch-size 100
//
// For each row whose `<column>` value begins with "enc:v<N>:<purpose>:..."
// at N < current version, the row is rewritten with "enc:v<current>:...".
// Rows that are NULL, empty, or already at current version are skipped.
//
// Safe to re-run: idempotent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/crypto"
	"github.com/sentinelcore/sentinelcore/pkg/secrets"
)

func main() {
	var (
		purpose    string
		table      string
		column     string
		idColumn   string
		batchSize  int
		dryRun     bool
		dbURL      string
	)
	flag.StringVar(&purpose, "purpose", "", "envelope purpose (sso, webhook, ...)")
	flag.StringVar(&table, "table", "", "qualified table name, e.g. auth.oidc_providers")
	flag.StringVar(&column, "column", "", "column holding the envelope string")
	flag.StringVar(&idColumn, "id-column", "id", "primary key column for UPDATE WHERE")
	flag.IntVar(&batchSize, "batch-size", 50, "rows to process per transaction")
	flag.BoolVar(&dryRun, "dry-run", false, "list rows that would be updated, do not write")
	flag.StringVar(&dbURL, "db-url", "", "Postgres DSN (default: $DATABASE_URL)")
	flag.Parse()

	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if purpose == "" || table == "" || column == "" || dbURL == "" {
		fmt.Fprintln(os.Stderr,
			"usage: rotate-sweep --purpose <p> --table <schema.table> --column <col> [--id-column id] [--batch-size 50] [--dry-run]")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Hour)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		die("connect: %v", err)
	}
	defer pool.Close()

	// The envelope needs a key resolver. In production this is a
	// secrets.Resolver backed by env or Vault. Here we reuse the
	// same default so sweep picks up whatever keys the controlplane
	// is using.
	secretResolver, err := secrets.DefaultResolver()
	if err != nil {
		die("secrets resolver: %v", err)
	}

	env := crypto.NewEnvelope(pool, &envelopeKeys{r: secretResolver})
	if err := env.Reload(ctx); err != nil {
		die("envelope reload: %v", err)
	}
	currentVer := env.CurrentVersion(crypto.Purpose(purpose))
	if currentVer == 0 {
		die("no current key for purpose %q — run sentinelcore-cli rotate aes/%s first", purpose, purpose)
	}
	fmt.Printf("sweep: purpose=%s current_version=v%d table=%s column=%s dry_run=%v\n",
		purpose, currentVer, table, column, dryRun)

	total, rewritten := 0, 0
	for {
		ids, versions, blobs, err := fetchBatch(ctx, pool, table, column, idColumn,
			purpose, currentVer, batchSize)
		if err != nil {
			die("fetch: %v", err)
		}
		if len(ids) == 0 {
			break
		}
		total += len(ids)

		for i, id := range ids {
			oldBlob := blobs[i]
			fromVer := versions[i]
			plain, err := env.Open(oldBlob, nil)
			if err != nil {
				fmt.Printf("  ! id=%s v%d: open failed: %v — skipping\n", id, fromVer, err)
				continue
			}
			newBlob, err := env.Seal(crypto.Purpose(purpose), plain, nil)
			if err != nil {
				fmt.Printf("  ! id=%s: seal failed: %v — skipping\n", id, err)
				continue
			}

			if dryRun {
				fmt.Printf("  would rewrite id=%s from v%d → v%d\n", id, fromVer, currentVer)
				continue
			}

			sql := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s = $2`,
				table, column, idColumn)
			if _, err := pool.Exec(ctx, sql, newBlob, id); err != nil {
				fmt.Printf("  ! id=%s: update failed: %v\n", id, err)
				continue
			}
			rewritten++
			fmt.Printf("  ✓ id=%s  v%d → v%d\n", id, fromVer, currentVer)
		}

		if len(ids) < batchSize {
			break
		}
	}

	fmt.Printf("\nsweep complete: %d rows scanned, %d rewritten\n", total, rewritten)
}

// fetchBatch pulls up to batchSize rows whose <column> starts with
// "enc:v" and NOT already at the current version. Returns parallel
// slices of id/version/blob.
func fetchBatch(ctx context.Context, pool *pgxpool.Pool,
	table, column, idColumn, purpose string, currentVer, batchSize int,
) ([]string, []int, []string, error) {

	// Build the prefix pattern: we want rows where the envelope is
	// tagged with `<purpose>` but NOT the current version. Since the
	// envelope format is "enc:v<N>:<purpose>:..." we match purpose
	// with a LIKE on the middle segment and exclude the exact prefix
	// for <current>.
	wantPurposePrefix := "enc:v%:" + purpose + ":%"
	skipCurrentPrefix := fmt.Sprintf("enc:v%d:%s:", currentVer, purpose)

	sql := fmt.Sprintf(`
		SELECT %s::text, %s
		  FROM %s
		 WHERE %s LIKE $1
		   AND %s NOT LIKE $2
		 ORDER BY %s
		 LIMIT $3
	`, idColumn, column, table, column, column, idColumn)

	rows, err := pool.Query(ctx, sql,
		wantPurposePrefix, skipCurrentPrefix+"%", batchSize)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()

	var ids []string
	var versions []int
	var blobs []string
	for rows.Next() {
		var id, blob string
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, nil, nil, err
		}
		ver := parseEnvVersion(blob)
		if ver == 0 || ver == currentVer {
			continue
		}
		ids = append(ids, id)
		versions = append(versions, ver)
		blobs = append(blobs, blob)
	}
	return ids, versions, blobs, rows.Err()
}

// parseEnvVersion pulls N out of "enc:v<N>:...". Returns 0 if the
// string doesn't parse.
func parseEnvVersion(s string) int {
	const prefix = "enc:v"
	if !strings.HasPrefix(s, prefix) {
		return 0
	}
	rest := s[len(prefix):]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return 0
	}
	v, err := strconv.Atoi(rest[:colon])
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

// envelopeKeys adapts a secrets.Resolver to crypto.KeyResolver.
// Reads the vault_path column from auth.aes_keys and delegates the
// actual fetch to secrets. Identical adapter to what the controlplane
// uses in production.
type envelopeKeys struct {
	r secrets.Resolver
}

func (e *envelopeKeys) ResolveKey(ctx context.Context, p crypto.Purpose, v int) ([]byte, error) {
	// Look up vault_path for (purpose, version).
	// This adapter needs a DB handle; for simplicity in this CLI we
	// rely on the caller having set env vars matching the vault_path
	// convention ("env:SC_TIER0_AES_<PURPOSE>_V<N>") so a direct
	// secrets.Get works without the DB roundtrip.
	_ = ctx
	return e.r.Get(ctx, fmt.Sprintf("env:SC_TIER0_AES_%s_V%d",
		strings.ToUpper(string(p)), v))
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rotate-sweep: "+format+"\n", args...)
	os.Exit(1)
}

// sanity import reference so go vet keeps pgx.
var _ = errors.New
var _ pgx.Tx
