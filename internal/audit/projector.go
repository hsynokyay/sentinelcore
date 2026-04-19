package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	pkgaudit "github.com/sentinelcore/sentinelcore/pkg/audit"
)

// RiskProjector materialises risk.* audit events into audit.risk_events.
// It runs inside the audit-service consumer — same transaction as the
// audit_log INSERT, so a failure to project rolls back the entire write
// and the NATS message is redelivered.
//
// Materiality filter (plan §4.2): score changes < 0.5 and "noisy"
// seen_again events skip the projection but still land in audit_log.
// The filter is evaluated on the before/after values in event.Details.
//
// Required details fields by action:
//
//   risk.created              risk_id (uuid)
//   risk.seen_again           risk_id, last_seen (ISO8601)
//   risk.score.changed        risk_id, before.score (float), after.score (float)
//   risk.status.changed       risk_id, before.status, after.status
//   risk.relation.added       risk_id, finding_id
//   risk.relation.removed     risk_id, finding_id
//   risk.evidence.changed     risk_id, before.fingerprint, after.fingerprint
//   risk.resolved             risk_id, note?
//   risk.reopened             risk_id, note?
//   risk.muted                risk_id, note?
//   risk.unmuted              risk_id, note?
//   risk.assigned             risk_id, before.assignee, after.assignee
//   risk.note.added           risk_id, note
//
// Missing risk_id is a projection error (the audit row still goes in).
type RiskProjector struct{}

// NewRiskProjector returns a zero-state projector. Stateless; safe to
// share across consumer goroutines.
func NewRiskProjector() *RiskProjector { return &RiskProjector{} }

// Project writes a risk_events row for a risk.* action if the event is
// "material" (see plan §4.2). Returns nil on skip so the caller always
// commits the parent transaction. Non-nil errors roll back the
// audit_log INSERT too — the NATS message will be redelivered.
func (p *RiskProjector) Project(
	ctx context.Context, tx pgx.Tx,
	auditLogID int64, e pkgaudit.AuditEvent,
) error {
	eventType, ok := actionToEventType(pkgaudit.Action(e.Action))
	if !ok {
		return nil // not a risk.* action we project
	}

	details := detailsMap(e.Details)
	riskID := firstString(details, "risk_id")
	if riskID == "" {
		return fmt.Errorf("projector: risk.%s event missing risk_id (audit_log_id=%d)",
			eventType, auditLogID)
	}

	before, after := beforeAfter(details)
	note := firstString(details, "note")

	material := assessMateriality(eventType, before, after, details)
	if !material {
		// Skip projection; audit_log still captures the event.
		return nil
	}

	ts, err := parseTimestamp(e.Timestamp)
	if err != nil {
		return fmt.Errorf("projector: parse ts: %w", err)
	}

	var beforeJSON, afterJSON []byte
	if len(before) > 0 {
		beforeJSON, _ = json.Marshal(before)
	}
	if len(after) > 0 {
		afterJSON, _ = json.Marshal(after)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO audit.risk_events (
		    risk_id, org_id, event_type, occurred_at,
		    actor_type, actor_id, audit_log_id, audit_log_ts,
		    before_value, after_value, note, is_material
		) VALUES (
		    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, true
		)
	`, riskID, e.OrgID, eventType, ts,
		e.ActorType, e.ActorID, auditLogID, ts,
		nullIfEmpty(beforeJSON), nullIfEmpty(afterJSON), nullIfEmptyStr(note))
	return err
}

// actionToEventType maps the full action code to the short event_type
// stored in audit.risk_events. Returns (_, false) for non-risk actions
// and for correlation.rebuild.triggered (which is a project-level event,
// not a per-risk one).
func actionToEventType(a pkgaudit.Action) (string, bool) {
	s := string(a)
	if !strings.HasPrefix(s, "risk.") {
		return "", false
	}
	switch a {
	case pkgaudit.RiskCreated:
		return "created", true
	case pkgaudit.RiskSeenAgain:
		return "seen_again", true
	case pkgaudit.RiskScoreChanged:
		return "score_changed", true
	case pkgaudit.RiskStatusChanged:
		return "status_changed", true
	case pkgaudit.RiskRelationAdded:
		return "relation_added", true
	case pkgaudit.RiskRelationRemoved:
		return "relation_removed", true
	case pkgaudit.RiskEvidenceChanged:
		return "evidence_changed", true
	case pkgaudit.RiskResolved:
		return "resolved", true
	case pkgaudit.RiskReopened:
		return "reopened", true
	case pkgaudit.RiskMuted:
		return "muted", true
	case pkgaudit.RiskUnmuted:
		return "unmuted", true
	case pkgaudit.RiskAssigned:
		return "assigned", true
	case pkgaudit.RiskNoteAdded:
		return "note_added", true
	}
	return "", false
}

// assessMateriality implements plan §4.2:
//
//   - created / status_changed / resolved / reopened / muted / unmuted /
//     assigned / note_added / relation_* / evidence_changed — ALWAYS
//   - score_changed — only if |after.score - before.score| >= 0.5
//   - seen_again — only if before.last_seen was >= 7 days ago
func assessMateriality(eventType string, before, after map[string]any, details map[string]any) bool {
	switch eventType {
	case "created", "status_changed", "resolved", "reopened",
		"muted", "unmuted", "assigned", "note_added",
		"relation_added", "relation_removed", "evidence_changed":
		return true
	case "score_changed":
		bs, _ := before["score"].(float64)
		as, _ := after["score"].(float64)
		delta := as - bs
		if delta < 0 {
			delta = -delta
		}
		return delta >= 0.5
	case "seen_again":
		// details.last_seen is the PRIOR timestamp, not the current one.
		last, ok := details["last_seen"].(string)
		if !ok {
			// No prior seen — treat as material (first re-detection).
			return true
		}
		t, err := time.Parse(time.RFC3339Nano, last)
		if err != nil {
			t, err = time.Parse(time.RFC3339, last)
		}
		if err != nil {
			return true
		}
		return time.Since(t) >= 7*24*time.Hour
	}
	return true
}

// detailsMap returns a map[string]any view of event.Details whether it
// came in as a real map, a json.RawMessage, or a typed struct.
func detailsMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

// beforeAfter extracts details.before and details.after (if present) as
// maps. Missing keys yield empty maps so the caller can inspect fields
// without nil-guards.
func beforeAfter(d map[string]any) (map[string]any, map[string]any) {
	before, _ := d["before"].(map[string]any)
	after, _ := d["after"].(map[string]any)
	if before == nil {
		before = map[string]any{}
	}
	if after == nil {
		after = map[string]any{}
	}
	return before, after
}

func firstString(d map[string]any, key string) string {
	if d == nil {
		return ""
	}
	s, _ := d[key].(string)
	return s
}

func nullIfEmpty(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullIfEmptyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Suppress unused-import warnings if the above is later simplified.
var _ = errors.New
