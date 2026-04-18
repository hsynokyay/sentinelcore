package audit

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pkgaudit "github.com/sentinelcore/sentinelcore/pkg/audit"
)

// HMACWriter is the chained, tamper-evident replacement for Writer.
//
// Invariants:
//   - At most ONE INSERT into a given partition is in flight at a time
//     (enforced via pg_advisory_xact_lock keyed on the partition name).
//   - previous_hash for a row is the entry_hash of the previous row IN THE
//     SAME PARTITION. Cross-partition boundary proofs live in a separate
//     `audit.partition_boundaries` table (added in a later chunk).
//   - Duplicate event_id is a silent-ok: UNIQUE(event_id, timestamp)
//     fires 23505 and the caller's dedup loop acks the NATS message.
//   - All DB operations happen in one transaction; a Commit failure
//     leaves the chain untouched.
type HMACWriter struct {
	pool *pgxpool.Pool
	keys pkgaudit.KeyResolver
}

// NewHMACWriter constructs a writer. The key resolver is responsible for
// surfacing ErrKeyMissing so the consumer can emit audit.hmac_key.missing.
func NewHMACWriter(pool *pgxpool.Pool, keys pkgaudit.KeyResolver) *HMACWriter {
	return &HMACWriter{pool: pool, keys: keys}
}

// WriteOne inserts a single event. The HMAC chain makes batch writes
// serial anyway (every row depends on the previous row's hash), so there
// is no advantage to a batch API here — keep the surface minimal.
//
// Returns (duplicate=true, nil) if the event_id was already persisted;
// consumer acks the NATS delivery in that case without emitting any
// operator-visible signal.
func (w *HMACWriter) WriteOne(ctx context.Context, e pkgaudit.AuditEvent) (duplicate bool, err error) {
	ts, err := parseTimestamp(e.Timestamp)
	if err != nil {
		return false, fmt.Errorf("hmac_writer: parse timestamp: %w", err)
	}

	keyVer := w.keys.CurrentVersion()
	key, err := w.keys.Key(keyVer)
	if err != nil {
		return false, fmt.Errorf("hmac_writer: key v%d: %w", keyVer, err)
	}

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("hmac_writer: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Serialise writes per partition. The lock is xact-scoped, released
	// automatically on commit/rollback. hash(partition_name) — int32 —
	// is fine as a lock id: collisions just mean a marginal wait on an
	// unrelated partition, not correctness impact.
	partition := partitionNameFor(ts)
	lockID := int64(fnvHash32(partition))
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockID); err != nil {
		return false, fmt.Errorf("hmac_writer: advisory lock: %w", err)
	}

	// Look up the previous row's entry_hash in the same partition.
	var prevHash string
	err = tx.QueryRow(ctx, fmt.Sprintf(`
		SELECT COALESCE(entry_hash, '')
		FROM audit.%s
		ORDER BY id DESC
		LIMIT 1
	`, quoteIdent(partition))).Scan(&prevHash)
	if errors.Is(err, pgx.ErrNoRows) {
		prevHash = ""
	} else if err != nil {
		return false, fmt.Errorf("hmac_writer: previous hash: %w", err)
	}

	canonical := pkgaudit.Canonical(e, prevHash)
	entryHash := pkgaudit.HMACCompute(key, canonical)

	// INET parse — invalid strings become NULL, matching the legacy path.
	var actorIP *netip.Addr
	if e.ActorIP != "" {
		if addr, err := netip.ParseAddr(e.ActorIP); err == nil {
			actorIP = &addr
		}
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit.audit_log (
		    event_id, timestamp, actor_type, actor_id, actor_ip,
		    action, resource_type, resource_id,
		    org_id, team_id, project_id, details, result,
		    previous_hash, entry_hash, hmac_key_version
		) VALUES (
		    $1, $2, $3, $4, $5,
		    $6, $7, $8,
		    $9, $10, $11, $12, $13,
		    $14, $15, $16
		)
	`, e.EventID, ts, e.ActorType, e.ActorID, actorIP,
		e.Action, e.ResourceType, e.ResourceID,
		parseNullableUUID(e.OrgID), parseNullableUUID(e.TeamID), parseNullableUUID(e.ProjectID),
		e.Details, e.Result,
		prevHash, entryHash, keyVer)
	if err != nil {
		if isUniqueViolation(err) {
			// Duplicate delivery — commit the empty tx (releases lock) and ack.
			return true, nil
		}
		return false, fmt.Errorf("hmac_writer: insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("hmac_writer: commit: %w", err)
	}
	return false, nil
}

// partitionNameFor returns "audit_log_YYYYMM" for a timestamp.
func partitionNameFor(t time.Time) string {
	t = t.UTC()
	return fmt.Sprintf("audit_log_%04d%02d", t.Year(), int(t.Month()))
}

// parseTimestamp accepts RFC3339Nano (what Emitter produces) plus plain
// RFC3339 for older producers.
func parseTimestamp(s string) (time.Time, error) {
	if s == "" {
		return time.Now().UTC(), nil
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp: %q", s)
}

// fnvHash32 is used only for the advisory-lock key; collisions cost a
// brief wait, not correctness.
func fnvHash32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// quoteIdent duplicates integrity.quoteIdent — kept local so the writer
// has no dependency on the verifier package.
func quoteIdent(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			out = append(out, '"', '"')
			continue
		}
		out = append(out, s[i])
	}
	out = append(out, '"')
	return string(out)
}

// isUniqueViolation returns true for PostgreSQL SQLSTATE 23505.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// Ensure uuid import stays used (parseNullableUUID defined in writer.go).
var _ = uuid.Nil
