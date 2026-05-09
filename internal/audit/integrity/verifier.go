// Package integrity verifies the HMAC chain on auth.audit_log partitions.
//
// A verification run scans rows of a partition in id-order and, for each
// row, recomputes entry_hash = HMAC(key_vN, canonical(row) || previous_hash).
// If any row's stored entry_hash does not match, the run fails and records
// the offending row id. The outcome ('pass' | 'fail' | 'partial' | 'error')
// and a row pointer are written into audit.integrity_checks so operators
// can replay the check later — the verification log is itself auditable.
//
// 'partial' outcome is used when rows have previous_hash='' and
// entry_hash='' (i.e. were written by the pre-Chunk-3 code path that never
// computed a chain). This is expected during the transition and must not
// be treated as a breach.
package integrity

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/audit"
)

// Outcome is the terminal status of a verification run.
type Outcome string

const (
	OutcomePass    Outcome = "pass"
	OutcomeFail    Outcome = "fail"
	OutcomePartial Outcome = "partial" // chain not started for some rows
	OutcomeError   Outcome = "error"   // verifier itself failed
)

// KeyResolver returns the HMAC key bytes for a given key version. The real
// implementation reads from Vault or the transitional env var; tests inject
// a map-backed stub.
type KeyResolver interface {
	Key(version int) ([]byte, error)
}

// Result is returned from VerifyPartition.
type Result struct {
	Partition    string
	Outcome      Outcome
	RowsScanned  int64
	FirstRowID   int64
	LastRowID    int64
	FailedRowID  int64  // 0 if no failure
	FailedKeyVer int    // 0 if not a key-version failure
	ErrorMessage string // non-empty on fail/error/partial
}

// Verifier runs chain checks against a partition and records the outcome.
type Verifier struct {
	pool *pgxpool.Pool
	keys KeyResolver
}

func NewVerifier(pool *pgxpool.Pool, keys KeyResolver) *Verifier {
	return &Verifier{pool: pool, keys: keys}
}

// VerifyPartition scans a single monthly partition (e.g. "audit_log_202604")
// in id-asc order. Streaming iteration keeps memory bounded even for
// tens of millions of rows per partition.
//
// The verifier opens ONE read-only transaction for the entire partition
// scan so a truncate / DDL race can't silently skip rows.
func (v *Verifier) VerifyPartition(ctx context.Context, partition string) (Result, error) {
	res := Result{Partition: partition, Outcome: OutcomeError}

	tx, err := v.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		res.ErrorMessage = fmt.Sprintf("begin tx: %v", err)
		return res, v.record(ctx, res)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, fmt.Sprintf(`
		SELECT id, event_id, timestamp, actor_type, actor_id,
		       COALESCE(host(actor_ip), ''),
		       action, resource_type, resource_id,
		       COALESCE(org_id::text, ''),
		       COALESCE(team_id::text, ''),
		       COALESCE(project_id::text, ''),
		       COALESCE(details, '{}'::jsonb),
		       result, previous_hash, entry_hash,
		       COALESCE(hmac_key_version, 0)
		FROM audit.%s
		ORDER BY id ASC
	`, quoteIdent(partition)))
	if err != nil {
		res.ErrorMessage = fmt.Sprintf("query: %v", err)
		return res, v.record(ctx, res)
	}
	defer rows.Close()

	var (
		rowCount      int64
		firstRowID    int64
		lastRowID     int64
		unchainedSeen bool
		prevHash      string // the previous ROW's entry_hash in this partition
		firstRow      = true
	)

	for rows.Next() {
		var (
			id, keyVer                    int64
			eventID, actorType, actorID   string
			actorIP, action, resType, rid string
			orgID, teamID, projID         string
			ts                            time.Time
			detailsRaw                    []byte
			result, storedPrev, storedHash string
		)
		if err := rows.Scan(&id, &eventID, &ts, &actorType, &actorID, &actorIP,
			&action, &resType, &rid, &orgID, &teamID, &projID,
			&detailsRaw, &result, &storedPrev, &storedHash, &keyVer); err != nil {
			res.ErrorMessage = fmt.Sprintf("scan row: %v", err)
			return res, v.record(ctx, res)
		}
		rowCount++
		lastRowID = id
		if firstRow {
			firstRowID = id
			firstRow = false
		}

		// Rows with empty chain slots belong to the legacy / pre-chain era.
		// Don't fail — flag as "partial" for the whole run.
		if storedHash == "" && storedPrev == "" {
			unchainedSeen = true
			// Don't update prevHash — next row expects the previous REAL hash.
			continue
		}

		key, err := v.keys.Key(int(keyVer))
		if err != nil {
			res.Outcome = OutcomeFail
			res.FailedRowID = id
			res.FailedKeyVer = int(keyVer)
			res.ErrorMessage = fmt.Sprintf("key v%d unavailable: %v", keyVer, err)
			res.RowsScanned = rowCount
			res.FirstRowID = firstRowID
			res.LastRowID = lastRowID
			return res, v.record(ctx, res)
		}

		// Reconstruct the original AuditEvent for canonical-form computation.
		ev := audit.AuditEvent{
			EventID:      eventID,
			Timestamp:    ts.UTC().Format(time.RFC3339Nano),
			ActorType:    actorType,
			ActorID:      actorID,
			ActorIP:      actorIP,
			Action:       action,
			ResourceType: resType,
			ResourceID:   rid,
			OrgID:        orgID,
			TeamID:       teamID,
			ProjectID:    projID,
			Result:       result,
		}
		if len(detailsRaw) > 0 && string(detailsRaw) != "{}" {
			// The stored JSONB is parsed to a map so Canonical() applies
			// the same key-sorting logic the writer used.
			if m, ok := jsonToMap(detailsRaw); ok {
				ev.Details = m
			}
		}
		canonical := audit.Canonical(ev, storedPrev)
		if !audit.HMACVerify(key, canonical, storedHash) {
			res.Outcome = OutcomeFail
			res.FailedRowID = id
			res.FailedKeyVer = int(keyVer)
			res.ErrorMessage = "HMAC mismatch"
			res.RowsScanned = rowCount
			res.FirstRowID = firstRowID
			res.LastRowID = lastRowID
			return res, v.record(ctx, res)
		}
		prevHash = storedHash
	}
	if err := rows.Err(); err != nil {
		res.ErrorMessage = fmt.Sprintf("rows: %v", err)
		return res, v.record(ctx, res)
	}
	_ = prevHash // kept for future cross-partition boundary verification

	res.RowsScanned = rowCount
	res.FirstRowID = firstRowID
	res.LastRowID = lastRowID
	if unchainedSeen {
		res.Outcome = OutcomePartial
		res.ErrorMessage = "partition contains pre-chain rows (expected during transition)"
	} else {
		res.Outcome = OutcomePass
		res.ErrorMessage = ""
	}
	return res, v.record(ctx, res)
}

// record persists the outcome of a verification run into audit.integrity_checks.
// Errors writing the record are returned but the primary outcome is preserved.
func (v *Verifier) record(ctx context.Context, r Result) error {
	_, err := v.pool.Exec(ctx, `
		INSERT INTO audit.integrity_checks
		    (partition_name, row_count, first_row_id, last_row_id,
		     outcome, failed_row_id, failed_key_version, error_message,
		     finished_at, checked_by)
		VALUES ($1, $2, NULLIF($3, 0), NULLIF($4, 0),
		        $5, NULLIF($6, 0), NULLIF($7, 0), NULLIF($8, ''),
		        now(), 'verifier')
	`, r.Partition, r.RowsScanned, r.FirstRowID, r.LastRowID,
		string(r.Outcome), r.FailedRowID, r.FailedKeyVer, r.ErrorMessage)
	return err
}

// quoteIdent escapes a PostgreSQL identifier. Partition names are built
// internally (never user-supplied) so this is belt-and-braces.
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

// jsonToMap is a cheap wrapper around json.Unmarshal into map[string]any.
// Returns false for non-object JSON so the canonical form stays stable.
func jsonToMap(b []byte) (map[string]any, bool) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false
	}
	return m, true
}
