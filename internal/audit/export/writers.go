// Package export renders audit rows into streaming CSV or NDJSON.
//
// Both writers flush after each row so the HTTP response starts moving
// immediately and the controlplane doesn't buffer megabytes of rows in
// RAM. Callers read rows from pgx.Rows and hand one AuditRow at a time
// to Write.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"
)

// AuditRow is the exportable view of an audit.audit_log row. Mirrors
// the column set exactly; keep field order stable — the CSV header does
// too and external compliance tooling may depend on it.
type AuditRow struct {
	ID             int64
	EventID        string
	Timestamp      time.Time
	ActorType      string
	ActorID        string
	ActorIP        string // host() of INET, may be empty
	Action         string
	ResourceType   string
	ResourceID     string
	OrgID          string
	TeamID         string
	ProjectID      string
	Details        []byte // raw JSONB bytes
	Result         string
	PreviousHash   string
	EntryHash      string
	HMACKeyVersion int
}

// ScanFrom reads a single pgx.Rows row into an AuditRow. The column list
// must match the Scan order here — kept in one place so drift is
// impossible.
type Rows interface {
	Scan(dst ...any) error
}

// ScanSelect is the column list callers pass to pgx.Query so ScanRow sees
// the expected order. A constant rather than a helper so static greps
// catch any divergence.
const ScanSelect = `id, event_id, timestamp, actor_type, actor_id,
	COALESCE(host(actor_ip), ''),
	action, resource_type, resource_id,
	COALESCE(org_id::text, ''), COALESCE(team_id::text, ''), COALESCE(project_id::text, ''),
	COALESCE(details, '{}'::jsonb),
	result, COALESCE(previous_hash, ''), COALESCE(entry_hash, ''),
	COALESCE(hmac_key_version, 0)`

// ScanRow populates an AuditRow. Caller owns the Rows object.
func ScanRow(r Rows, out *AuditRow) error {
	var ts time.Time
	var detailsRaw []byte
	err := r.Scan(&out.ID, &out.EventID, &ts, &out.ActorType, &out.ActorID,
		&out.ActorIP, &out.Action, &out.ResourceType, &out.ResourceID,
		&out.OrgID, &out.TeamID, &out.ProjectID, &detailsRaw,
		&out.Result, &out.PreviousHash, &out.EntryHash, &out.HMACKeyVersion)
	if err != nil {
		return fmt.Errorf("export.ScanRow: %w", err)
	}
	out.Timestamp = ts
	out.Details = detailsRaw
	// Final sanitation: ensure IP looks like an IP and not a parser leak.
	if out.ActorIP != "" {
		if _, err := netip.ParseAddr(out.ActorIP); err != nil {
			out.ActorIP = ""
		}
	}
	return nil
}

// ---------- CSV ----------

// CSVWriter flushes each row before proceeding. Headers are emitted by
// the first WriteHeader call.
type CSVWriter struct {
	w    *csv.Writer
	sink io.Writer
}

func NewCSVWriter(w io.Writer) *CSVWriter {
	return &CSVWriter{w: csv.NewWriter(w), sink: w}
}

// Header order is fixed. Compliance tools and downstream audit systems
// key off the first row.
var csvHeader = []string{
	"id", "event_id", "timestamp", "actor_type", "actor_id", "actor_ip",
	"action", "resource_type", "resource_id",
	"org_id", "team_id", "project_id",
	"details_json", "result", "previous_hash", "entry_hash", "hmac_key_version",
}

func (c *CSVWriter) WriteHeader() error {
	if err := c.w.Write(csvHeader); err != nil {
		return err
	}
	c.w.Flush()
	return c.w.Error()
}

func (c *CSVWriter) Write(r AuditRow) error {
	detailsStr := ""
	if len(r.Details) > 0 {
		detailsStr = string(r.Details)
	}
	record := []string{
		strconv.FormatInt(r.ID, 10),
		r.EventID,
		r.Timestamp.UTC().Format(time.RFC3339Nano),
		r.ActorType,
		r.ActorID,
		r.ActorIP,
		r.Action,
		r.ResourceType,
		r.ResourceID,
		r.OrgID, r.TeamID, r.ProjectID,
		detailsStr,
		r.Result,
		r.PreviousHash,
		r.EntryHash,
		strconv.Itoa(r.HMACKeyVersion),
	}
	if err := c.w.Write(record); err != nil {
		return err
	}
	c.w.Flush()
	return c.w.Error()
}

// ---------- NDJSON ----------

// NDJSONWriter emits one JSON object per line. Compact, no whitespace.
// Ordering of keys uses Go's default struct encoding — same across runs.
type NDJSONWriter struct {
	w   io.Writer
	buf []byte
}

func NewNDJSONWriter(w io.Writer) *NDJSONWriter {
	return &NDJSONWriter{w: w}
}

// NDJSON has no header; WriteHeader is a no-op so the two writers share
// a uniform interface from the caller's perspective.
func (n *NDJSONWriter) WriteHeader() error { return nil }

type ndjsonShape struct {
	ID             int64           `json:"id"`
	EventID        string          `json:"event_id"`
	Timestamp      string          `json:"timestamp"`
	ActorType      string          `json:"actor_type"`
	ActorID        string          `json:"actor_id"`
	ActorIP        string          `json:"actor_ip,omitempty"`
	Action         string          `json:"action"`
	ResourceType   string          `json:"resource_type"`
	ResourceID     string          `json:"resource_id"`
	OrgID          string          `json:"org_id,omitempty"`
	TeamID         string          `json:"team_id,omitempty"`
	ProjectID      string          `json:"project_id,omitempty"`
	Details        json.RawMessage `json:"details,omitempty"`
	Result         string          `json:"result"`
	PreviousHash   string          `json:"previous_hash,omitempty"`
	EntryHash      string          `json:"entry_hash,omitempty"`
	HMACKeyVersion int             `json:"hmac_key_version,omitempty"`
}

func (n *NDJSONWriter) Write(r AuditRow) error {
	s := ndjsonShape{
		ID: r.ID, EventID: r.EventID,
		Timestamp: r.Timestamp.UTC().Format(time.RFC3339Nano),
		ActorType: r.ActorType, ActorID: r.ActorID, ActorIP: r.ActorIP,
		Action: r.Action, ResourceType: r.ResourceType, ResourceID: r.ResourceID,
		OrgID: r.OrgID, TeamID: r.TeamID, ProjectID: r.ProjectID,
		Result: r.Result, PreviousHash: r.PreviousHash, EntryHash: r.EntryHash,
		HMACKeyVersion: r.HMACKeyVersion,
	}
	if len(r.Details) > 0 && string(r.Details) != "{}" {
		s.Details = json.RawMessage(r.Details)
	}
	// Reusable buffer keeps allocations low on large exports.
	n.buf = n.buf[:0]
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	n.buf = append(n.buf, b...)
	n.buf = append(n.buf, '\n')
	if _, err := n.w.Write(n.buf); err != nil {
		return err
	}
	return nil
}
