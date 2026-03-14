package audit

import (
	"context"
	"net/netip"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	pkgaudit "github.com/sentinelcore/sentinelcore/pkg/audit"
)

// Writer persists audit events to PostgreSQL in append-only fashion.
type Writer struct {
	pool *pgxpool.Pool
}

// NewWriter creates a Writer backed by the given connection pool.
func NewWriter(pool *pgxpool.Pool) *Writer {
	return &Writer{pool: pool}
}

// WriteBatch inserts a slice of audit events into audit.audit_log within a
// single transaction. On error the transaction is rolled back and messages
// should not be acknowledged so they can be redelivered.
func (w *Writer) WriteBatch(ctx context.Context, events []pkgaudit.AuditEvent) error {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	for _, e := range events {
		var actorIP *netip.Addr
		if e.ActorIP != "" {
			addr, err := netip.ParseAddr(e.ActorIP)
			if err == nil {
				actorIP = &addr
			}
		}

		_, err := tx.Exec(ctx,
			`INSERT INTO audit.audit_log
				(event_id, timestamp, actor_type, actor_id, actor_ip,
				 action, resource_type, resource_id,
				 org_id, team_id, project_id, details, result,
				 previous_hash, entry_hash)
			 VALUES
				($1, $2, $3, $4, $5,
				 $6, $7, $8,
				 $9, $10, $11, $12, $13,
				 '', '')`,
			e.EventID, e.Timestamp, e.ActorType, e.ActorID, actorIP,
			e.Action, e.ResourceType, e.ResourceID,
			parseNullableUUID(e.OrgID), parseNullableUUID(e.TeamID), parseNullableUUID(e.ProjectID),
			e.Details, e.Result,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// parseNullableUUID returns a *uuid.UUID if s is a valid UUID string, or nil
// if s is empty. This maps Go empty strings to SQL NULLs for nullable UUID
// columns.
func parseNullableUUID(s string) *uuid.UUID {
	if s == "" {
		return nil
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &u
}
