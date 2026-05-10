// Package evidence builds ZIP-format "evidence packs" — self-contained
// archives that bundle every artefact a regulator or external auditor needs
// to defend a risk-closure decision: the risk + finding records, the
// resolved compliance controls, the timeline of state transitions, the
// approval decision history, and the SLA / org policy that was in force at
// export time.
//
// The public entry points are:
//
//   - BuildPack — production code path. Loads everything from Postgres
//     using the supplied *pgxpool.Pool, then calls BuildPackFromData.
//   - BuildPackFromData — pure function used by tests. Takes a fully
//     populated PackData and writes the ZIP to an io.Writer.
//
// The split lets unit tests run without Postgres or MinIO; the data-loading
// path is exercised by integration tests that have TEST_DATABASE_URL set.
package evidence

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SchemaVersion of the manifest format. Bump when the file layout changes.
const SchemaVersion = "1.0.0"

// Scope describes the data slice a pack should contain.
//
// Kind is one of: "risk_evidence_pack", "project_evidence_pack", "custom".
// RiskIDs / ProjectID / Statuses / Since may all be set — they are AND-ed
// when filtering in the loader.
type Scope struct {
	Kind      string      `json:"kind"`
	RiskIDs   []uuid.UUID `json:"risk_ids,omitempty"`
	ProjectID *uuid.UUID  `json:"project_id,omitempty"`
	Since     *time.Time  `json:"since,omitempty"`
	Statuses  []string    `json:"statuses,omitempty"`
}

// Risk is a flat representation of a risk.cluster row.
type Risk struct {
	ID            uuid.UUID `json:"id"`
	ProjectID     uuid.UUID `json:"project_id,omitempty"`
	Title         string    `json:"title"`
	VulnClass     string    `json:"vuln_class"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	RiskScore     int       `json:"risk_score"`
	CWE           int       `json:"cwe_id,omitempty"`
	OWASPCategory string    `json:"owasp_category,omitempty"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
}

// Finding is a flat representation of a findings.findings row.
type Finding struct {
	ID          uuid.UUID `json:"id"`
	RiskID      uuid.UUID `json:"risk_id,omitempty"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	FindingType string    `json:"finding_type"`
	RuleID      string    `json:"rule_id,omitempty"`
	Description string    `json:"description,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	LineStart   int       `json:"line_start,omitempty"`
	URL         string    `json:"url,omitempty"`
	HTTPMethod  string    `json:"http_method,omitempty"`
	Parameter   string    `json:"parameter,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// ControlRef is a flattened compliance.ControlRef. Mirrors the shape used by
// the SARIF exporter so the same DB-layer resolver feeds both.
type ControlRef struct {
	CatalogCode string `json:"catalog_code"`
	CatalogName string `json:"catalog_name"`
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Confidence  string `json:"confidence,omitempty"`
}

// TimelineEvent is one row of the consolidated timeline. Sources include
// finding first-seen, transition history, approval submission/decision
// timestamps, and SLA breach events.
type TimelineEvent struct {
	At           time.Time `json:"at"`
	Kind         string    `json:"kind"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Detail       string    `json:"detail,omitempty"`
}

// AuditEntry mirrors audit.audit_log columns relevant to evidence export.
type AuditEntry struct {
	Timestamp    time.Time      `json:"timestamp"`
	Action       string         `json:"action"`
	ActorType    string         `json:"actor_type,omitempty"`
	ActorID      string         `json:"actor_id"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Result       string         `json:"result,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

// ApprovalDecision mirrors a row of governance.approval_decisions.
type ApprovalDecision struct {
	ApprovalID uuid.UUID `json:"approval_id"`
	Decision   string    `json:"decision"`
	DecidedBy  uuid.UUID `json:"decided_by"`
	DecidedAt  time.Time `json:"decided_at"`
	Reason     string    `json:"reason,omitempty"`
}

// PackData is the in-memory payload BuildPackFromData consumes. The
// production loader (BuildPack below) populates one of these from Postgres;
// tests build a fixture directly.
type PackData struct {
	OrgID    uuid.UUID
	Scope    Scope
	Format   string
	BuiltAt  time.Time
	BuiltBy  uuid.UUID

	Risks             []Risk
	Findings          []Finding
	Controls          []ControlRef
	TimelineEvents    []TimelineEvent
	AuditEntries      []AuditEntry
	ApprovalDecisions []ApprovalDecision
	SLAPolicy         map[string]any
	OrgSettings       map[string]any
}

// FileEntry is one row of manifest.files.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is the JSON document at manifest.json — the canonical index of
// the bundle plus high-level metadata.
type Manifest struct {
	SchemaVersion string      `json:"schema_version"`
	Format        string      `json:"format"`
	OrgID         string      `json:"org_id"`
	Scope         Scope       `json:"scope"`
	BuiltAt       time.Time   `json:"built_at"`
	BuiltBy       string      `json:"built_by"`
	Counts        Counts      `json:"counts"`
	Files         []FileEntry `json:"files"`
}

// Counts is a coarse summary embedded in the manifest so a reviewer can spot
// an empty / mismatched pack at a glance.
type Counts struct {
	Risks             int `json:"risks"`
	Findings          int `json:"findings"`
	Controls          int `json:"controls"`
	TimelineEvents    int `json:"timeline_events"`
	AuditEntries      int `json:"audit_entries"`
	ApprovalDecisions int `json:"approval_decisions"`
}

// BuildMeta is the result of a successful pack build.
type BuildMeta struct {
	Size   int64       // total bytes streamed to the writer
	SHA256 string      // hex SHA-256 of the entire ZIP payload
	Files  []FileEntry // per-file entries (also embedded in manifest.json)
}

// BuildPackFromData writes a ZIP-format evidence pack to w using the
// supplied PackData. Returns BuildMeta with the overall SHA-256 and the
// per-file manifest entries.
//
// The function is deterministic for a given PackData (no embedded timestamps
// other than data.BuiltAt; ZIP modtimes are zeroed) so retries produce
// byte-identical output — useful for content-addressing artefacts.
func BuildPackFromData(_ context.Context, data PackData, w io.Writer) (BuildMeta, error) {
	if data.Format == "" {
		data.Format = "zip_json"
	}

	// Collect per-file SHA-256 + size while we stream to the ZIP.
	var entries []FileEntry

	// Stage 1: write all data files into a temp buffer so we can compute
	// per-file digests, then assemble manifest.json + README.md, then write
	// everything to w in a single pass. We can't use a streaming
	// MultiWriter because the manifest depends on the digests of every
	// other file.
	stagedFiles := make([]stagedFile, 0, 16)

	addJSON := func(path string, payload any) error {
		buf, err := encodeJSON(payload)
		if err != nil {
			return fmt.Errorf("encode %s: %w", path, err)
		}
		stagedFiles = append(stagedFiles, stagedFile{path: path, body: buf})
		return nil
	}
	addRaw := func(path string, body []byte) {
		stagedFiles = append(stagedFiles, stagedFile{path: path, body: body})
	}

	// One JSON file per risk so a reviewer can pull out a single risk
	// without parsing a megabyte aggregate. Findings get the same
	// treatment, keyed by their UUID.
	for i := range data.Risks {
		r := data.Risks[i]
		if err := addJSON(fmt.Sprintf("risks/%s.json", r.ID), r); err != nil {
			return BuildMeta{}, err
		}
	}
	for i := range data.Findings {
		f := data.Findings[i]
		if err := addJSON(fmt.Sprintf("findings/%s.json", f.ID), f); err != nil {
			return BuildMeta{}, err
		}
	}

	// Aggregates.
	if err := addJSON("compliance/controls.json", controlsBundle{Controls: data.Controls}); err != nil {
		return BuildMeta{}, err
	}
	if err := addJSON("timeline/events.json", timelineBundle{Events: data.TimelineEvents}); err != nil {
		return BuildMeta{}, err
	}
	if err := addJSON("audit/log.json", auditBundle{Entries: data.AuditEntries}); err != nil {
		return BuildMeta{}, err
	}
	if err := addJSON("approvals/decisions.json", approvalsBundle{Decisions: data.ApprovalDecisions}); err != nil {
		return BuildMeta{}, err
	}
	if err := addJSON("policy/sla_policy.json", data.SLAPolicy); err != nil {
		return BuildMeta{}, err
	}
	if err := addJSON("policy/org_settings.json", data.OrgSettings); err != nil {
		return BuildMeta{}, err
	}

	// signature.txt is a stub — proper KMS-backed signing is a Phase 6
	// follow-up. We emit a placeholder so downstream tooling can target the
	// path today and we can swap in a real signature without changing the
	// bundle layout.
	addRaw("signature.txt", []byte("# evidence pack signature stub — KMS detached signature TBD\n"))

	// README.md — human-readable summary.
	addRaw("README.md", buildReadme(data))

	// Sort staged files by path so manifest order is deterministic.
	sort.SliceStable(stagedFiles, func(i, j int) bool {
		return stagedFiles[i].path < stagedFiles[j].path
	})

	// Compute per-file digests + entries.
	for i := range stagedFiles {
		sum := sha256.Sum256(stagedFiles[i].body)
		entries = append(entries, FileEntry{
			Path:   stagedFiles[i].path,
			Size:   int64(len(stagedFiles[i].body)),
			SHA256: hex.EncodeToString(sum[:]),
		})
	}

	// Build manifest.json (it includes digests of every other file).
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Format:        data.Format,
		OrgID:         data.OrgID.String(),
		Scope:         data.Scope,
		BuiltAt:       data.BuiltAt,
		BuiltBy:       data.BuiltBy.String(),
		Counts: Counts{
			Risks:             len(data.Risks),
			Findings:          len(data.Findings),
			Controls:          len(data.Controls),
			TimelineEvents:    len(data.TimelineEvents),
			AuditEntries:      len(data.AuditEntries),
			ApprovalDecisions: len(data.ApprovalDecisions),
		},
		Files: entries,
	}
	manifestBytes, err := encodeJSON(manifest)
	if err != nil {
		return BuildMeta{}, fmt.Errorf("encode manifest: %w", err)
	}

	// Stage 2: stream everything to w + sha256 hasher in one pass.
	overall := sha256.New()
	tee := io.MultiWriter(w, overall)
	counted := &countingWriter{w: tee}
	zw := zip.NewWriter(counted)

	// manifest.json first — auditors may scan it without unpacking the
	// whole archive.
	if err := writeZipFile(zw, "manifest.json", manifestBytes); err != nil {
		return BuildMeta{}, err
	}
	for i := range stagedFiles {
		if err := writeZipFile(zw, stagedFiles[i].path, stagedFiles[i].body); err != nil {
			return BuildMeta{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return BuildMeta{}, fmt.Errorf("zip close: %w", err)
	}

	return BuildMeta{
		Size:   counted.n,
		SHA256: hex.EncodeToString(overall.Sum(nil)),
		Files:  entries,
	}, nil
}

type stagedFile struct {
	path string
	body []byte
}

type controlsBundle struct {
	Controls []ControlRef `json:"controls"`
}
type timelineBundle struct {
	Events []TimelineEvent `json:"events"`
}
type auditBundle struct {
	Entries []AuditEntry `json:"entries"`
}
type approvalsBundle struct {
	Decisions []ApprovalDecision `json:"decisions"`
}

// encodeJSON writes a deterministic JSON encoding (sorted keys, no HTML
// escaping, trailing newline) so re-running BuildPackFromData on identical
// data produces identical bytes.
func encodeJSON(v any) ([]byte, error) {
	if v == nil {
		v = map[string]any{}
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	return b, nil
}

// writeZipFile creates a ZIP entry with a deterministic header (zero
// modtime). Using zip.FileHeader.Modified would embed the wall clock and
// break determinism.
func writeZipFile(zw *zip.Writer, name string, body []byte) error {
	hdr := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	// Deterministic archive: zero Modified makes archive/zip default the
	// MS-DOS modtime fields to 1980-01-01 so packs are bit-stable across
	// runs. Assigning the field directly avoids the deprecated SetModTime
	// helper (SA1019).
	hdr.Modified = time.Time{}
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// countingWriter tracks the number of bytes written so callers know the
// exact ZIP size without seeking.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// buildReadme renders a short human-readable summary of the pack contents.
// The format is intentionally simple Markdown — auditors skim, they don't
// render.
func buildReadme(data PackData) []byte {
	var b strings.Builder
	b.WriteString("# SentinelCore Evidence Pack\n\n")
	fmt.Fprintf(&b, "- **Org:** `%s`\n", data.OrgID)
	fmt.Fprintf(&b, "- **Scope kind:** `%s`\n", data.Scope.Kind)
	if len(data.Scope.RiskIDs) > 0 {
		ids := make([]string, len(data.Scope.RiskIDs))
		for i := range data.Scope.RiskIDs {
			ids[i] = data.Scope.RiskIDs[i].String()
		}
		fmt.Fprintf(&b, "- **Risk IDs:** %s\n", strings.Join(ids, ", "))
	}
	if data.Scope.ProjectID != nil {
		fmt.Fprintf(&b, "- **Project:** `%s`\n", data.Scope.ProjectID.String())
	}
	fmt.Fprintf(&b, "- **Built at:** `%s`\n", data.BuiltAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Built by:** `%s`\n", data.BuiltBy)
	b.WriteString("\n## Contents\n\n")
	fmt.Fprintf(&b, "- %d risk(s)\n", len(data.Risks))
	fmt.Fprintf(&b, "- %d finding(s)\n", len(data.Findings))
	fmt.Fprintf(&b, "- %d compliance control reference(s)\n", len(data.Controls))
	fmt.Fprintf(&b, "- %d timeline event(s)\n", len(data.TimelineEvents))
	fmt.Fprintf(&b, "- %d audit log entry/entries\n", len(data.AuditEntries))
	fmt.Fprintf(&b, "- %d approval decision(s)\n", len(data.ApprovalDecisions))
	b.WriteString("\n## Verification\n\n")
	b.WriteString("`manifest.json` lists every file with its SHA-256. ")
	b.WriteString("`signature.txt` will hold the KMS-backed detached signature ")
	b.WriteString("once Phase 6 KMS pinning is wired through.\n")
	return []byte(b.String())
}
