// Package evidence_test verifies the evidence pack ZIP builder produces a
// well-formed bundle with all the files the plan §6 mandates.
//
// We test the PURE layer — BuildPackFromData — so the test runs without
// Postgres or MinIO. The production wrapper BuildPack (which loads data
// from a *pgxpool.Pool) is exercised by the API integration test in
// internal/controlplane/api when TEST_DATABASE_URL is set.
package evidence_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/export/evidence"
)

// TestBuildEvidencePack_ContainsExpectedFiles asserts that the ZIP bundle
// contains every artefact the manifest schema lists, indexed by stable
// filename, plus a manifest with per-file SHA-256 entries.
func TestBuildEvidencePack_ContainsExpectedFiles(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	riskID := uuid.New()
	findingID := uuid.New()

	data := evidence.PackData{
		OrgID:    orgID,
		Scope:    evidence.Scope{Kind: "risk_evidence_pack", RiskIDs: []uuid.UUID{riskID}},
		Format:   "zip_json",
		BuiltAt:  time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		BuiltBy:  uuid.New(),
		Risks: []evidence.Risk{{
			ID:          riskID,
			Title:       "SQL Injection in /api/v1/users",
			VulnClass:   "sqli",
			Severity:    "high",
			Status:      "active",
			RiskScore:   75,
			FirstSeenAt: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			LastSeenAt:  time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			CWE:         89,
		}},
		Findings: []evidence.Finding{{
			ID:          findingID,
			RiskID:      riskID,
			Title:       "SQL Injection",
			Severity:    "high",
			Status:      "open",
			FindingType: "sast",
			RuleID:      "sast.sqli.v1",
			Description: "Unsanitised user input in query.",
			FilePath:    "src/users.go",
			LineStart:   42,
			CreatedAt:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		}},
		Controls: []evidence.ControlRef{{
			CatalogCode: "OWASP_TOP10_2021",
			CatalogName: "OWASP Top 10 (2021)",
			ControlID:   "A03",
			Title:       "Injection",
			Confidence:  "high",
		}},
		TimelineEvents: []evidence.TimelineEvent{{
			At:           time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
			Kind:         "finding.first_seen",
			ResourceType: "finding",
			ResourceID:   findingID.String(),
			Detail:       "Finding first observed",
		}},
		AuditEntries: []evidence.AuditEntry{{
			Timestamp:    time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC),
			Action:       "governance.approval.created",
			ActorID:      "user-1",
			ResourceType: "finding",
			ResourceID:   findingID.String(),
			Result:       "success",
		}},
		ApprovalDecisions: []evidence.ApprovalDecision{{
			ApprovalID: uuid.New(),
			Decision:   "approve",
			DecidedBy:  uuid.New(),
			DecidedAt:  time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC),
			Reason:     "Reviewed and acknowledged.",
		}},
		SLAPolicy: map[string]any{
			"critical": 1, "high": 7, "medium": 30, "low": 90,
		},
		OrgSettings: map[string]any{
			"require_closure_approval":   true,
			"require_two_person_closure": false,
		},
	}

	buf := &bytes.Buffer{}
	meta, err := evidence.BuildPackFromData(ctx, data, buf)
	if err != nil {
		t.Fatalf("BuildPackFromData: %v", err)
	}
	if meta.Size <= 0 {
		t.Fatalf("expected positive size, got %d", meta.Size)
	}
	if len(meta.SHA256) != 64 {
		t.Fatalf("expected 64-hex-char SHA-256, got %q", meta.SHA256)
	}
	if len(meta.Files) == 0 {
		t.Fatalf("expected per-file manifest entries, got 0")
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}

	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}

	required := []string{
		"manifest.json",
		"README.md",
		fmt.Sprintf("risks/%s.json", riskID),
		"compliance/controls.json",
		"timeline/events.json",
		"audit/log.json",
		"approvals/decisions.json",
		"policy/sla_policy.json",
		"policy/org_settings.json",
	}
	for _, want := range required {
		if !names[want] {
			t.Errorf("missing file in bundle: %s", want)
		}
	}

	// manifest.json must be parseable and list every file.
	manifestBytes := readZipFile(t, zr, "manifest.json")
	var m evidence.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		t.Fatalf("manifest.json invalid: %v", err)
	}
	if m.SchemaVersion == "" {
		t.Errorf("manifest missing schema_version")
	}
	if m.OrgID != orgID.String() {
		t.Errorf("manifest org_id mismatch: got %s want %s", m.OrgID, orgID.String())
	}
	if len(m.Files) == 0 {
		t.Errorf("manifest.files is empty")
	}
	// Every file that we found in the ZIP (except manifest.json itself) must
	// have a corresponding entry in manifest.files with a SHA-256.
	listed := map[string]string{}
	for _, fe := range m.Files {
		listed[fe.Path] = fe.SHA256
	}
	for name := range names {
		if name == "manifest.json" {
			continue
		}
		got, ok := listed[name]
		if !ok {
			t.Errorf("manifest.files missing entry for %s", name)
			continue
		}
		if len(got) != 64 {
			t.Errorf("file %s has invalid sha256 len %d", name, len(got))
		}
	}
}

// TestBuildEvidencePack_DeterministicHashes checks that re-building the same
// data with the same BuiltAt produces the same per-file SHA-256 entries.
func TestBuildEvidencePack_DeterministicHashes(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()

	data := evidence.PackData{
		OrgID:   orgID,
		Scope:   evidence.Scope{Kind: "project_evidence_pack"},
		Format:  "zip_json",
		BuiltAt: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		BuiltBy: uuid.New(),
	}

	buf1, buf2 := &bytes.Buffer{}, &bytes.Buffer{}
	if _, err := evidence.BuildPackFromData(ctx, data, buf1); err != nil {
		t.Fatalf("first build: %v", err)
	}
	if _, err := evidence.BuildPackFromData(ctx, data, buf2); err != nil {
		t.Fatalf("second build: %v", err)
	}

	manifest1 := readManifestFromZip(t, buf1.Bytes())
	manifest2 := readManifestFromZip(t, buf2.Bytes())

	if len(manifest1.Files) != len(manifest2.Files) {
		t.Fatalf("file count differs: %d vs %d", len(manifest1.Files), len(manifest2.Files))
	}
	for i := range manifest1.Files {
		if manifest1.Files[i].Path != manifest2.Files[i].Path {
			t.Errorf("file order differs at %d: %s vs %s", i, manifest1.Files[i].Path, manifest2.Files[i].Path)
		}
		if manifest1.Files[i].SHA256 != manifest2.Files[i].SHA256 {
			t.Errorf("hash differs for %s: %s vs %s",
				manifest1.Files[i].Path,
				manifest1.Files[i].SHA256,
				manifest2.Files[i].SHA256)
		}
	}
}

// TestBuildEvidencePack_ReadmeMentionsScope asserts the human-readable
// README.md highlights the export scope so a reviewer downloading the bundle
// has immediate context.
func TestBuildEvidencePack_ReadmeMentionsScope(t *testing.T) {
	ctx := context.Background()
	riskID := uuid.New()

	data := evidence.PackData{
		OrgID:   uuid.New(),
		Scope:   evidence.Scope{Kind: "risk_evidence_pack", RiskIDs: []uuid.UUID{riskID}},
		Format:  "zip_json",
		BuiltAt: time.Now().UTC(),
		BuiltBy: uuid.New(),
	}

	buf := &bytes.Buffer{}
	if _, err := evidence.BuildPackFromData(ctx, data, buf); err != nil {
		t.Fatalf("BuildPackFromData: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	readme := string(readZipFile(t, zr, "README.md"))
	if !strings.Contains(readme, "risk_evidence_pack") {
		t.Errorf("README.md should mention scope kind, got: %s", readme)
	}
}

func readZipFile(t *testing.T, zr *zip.Reader, name string) []byte {
	t.Helper()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return b
	}
	t.Fatalf("file not found in zip: %s", name)
	return nil
}

func readManifestFromZip(t *testing.T, raw []byte) evidence.Manifest {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("zip.NewReader: %v", err)
	}
	b := readZipFile(t, zr, "manifest.json")
	var m evidence.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("manifest unmarshal: %v", err)
	}
	return m
}
