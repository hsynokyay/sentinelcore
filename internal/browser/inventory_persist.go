package browser

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// PersistInventory writes surface inventory entries to the database.
// Uses INSERT ... ON CONFLICT to upsert: new entries are inserted,
// existing entries update last_seen_at and scan_count.
func PersistInventory(ctx context.Context, pool *pgxpool.Pool, inv *SurfaceInventory, logger zerolog.Logger) error {
	if inv == nil || len(inv.Entries) == 0 {
		return nil
	}
	if pool == nil {
		return fmt.Errorf("persist inventory: nil pool")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("persist inventory: acquire conn: %w", err)
	}
	defer conn.Release()

	inserted := 0
	updated := 0

	for _, entry := range inv.Entries {
		metadata, _ := json.Marshal(entry.Metadata)

		tag, err := conn.Exec(ctx,
			`INSERT INTO scans.surface_entries
				(id, project_id, scan_job_id, surface_type, url, method, exposure,
				 title, metadata, first_seen_at, last_seen_at, scan_count,
				 finding_ids, observation_count)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			 ON CONFLICT (id) DO UPDATE SET
				last_seen_at = EXCLUDED.last_seen_at,
				scan_count = scans.surface_entries.scan_count + 1,
				finding_ids = EXCLUDED.finding_ids,
				observation_count = EXCLUDED.observation_count,
				exposure = CASE
					WHEN EXCLUDED.exposure != 'unknown' THEN EXCLUDED.exposure
					ELSE scans.surface_entries.exposure
				END`,
			entry.ID,
			inv.ProjectID,
			inv.ScanJobID,
			string(entry.Type),
			entry.URL,
			entry.Method,
			string(entry.Exposure),
			entry.Title,
			metadata,
			entry.FirstSeenAt,
			entry.LastSeenAt,
			entry.ScanCount,
			entry.FindingIDs,
			entry.ObservationCount,
		)
		if err != nil {
			logger.Warn().Err(err).Str("entry_id", entry.ID).Msg("failed to upsert surface entry")
			continue
		}
		if tag.RowsAffected() > 0 {
			inserted++
		} else {
			updated++
		}
	}

	logger.Info().
		Int("inserted", inserted).
		Int("updated", updated).
		Int("total", len(inv.Entries)).
		Msg("surface inventory persisted")

	return nil
}
