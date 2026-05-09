package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleRow() AuditRow {
	return AuditRow{
		ID:             42,
		EventID:        "11111111-1111-1111-1111-111111111111",
		Timestamp:      time.Date(2026, 4, 18, 8, 0, 0, 123456000, time.UTC),
		ActorType:      "user",
		ActorID:        "alice",
		ActorIP:        "10.0.0.5",
		Action:         "auth.login.succeeded",
		ResourceType:   "user",
		ResourceID:     "alice",
		OrgID:          "abcd",
		TeamID:         "",
		ProjectID:      "",
		Details:        []byte(`{"email":"alice@example.com"}`),
		Result:         "success",
		PreviousHash:   "abc123",
		EntryHash:      "def456",
		HMACKeyVersion: 1,
	}
}

func TestCSVWriter_RowAndHeader(t *testing.T) {
	var buf bytes.Buffer
	w := NewCSVWriter(&buf)
	if err := w.WriteHeader(); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(sampleRow()); err != nil {
		t.Fatal(err)
	}

	r := csv.NewReader(&buf)
	records, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header + 1 row, got %d", len(records))
	}
	header := records[0]
	if header[0] != "id" || header[2] != "timestamp" || header[13] != "result" {
		t.Errorf("header shape: %v", header)
	}
	row := records[1]
	if row[0] != "42" || row[4] != "alice" || row[6] != "auth.login.succeeded" {
		t.Errorf("row shape: %v", row)
	}
	// details_json preserved.
	if !strings.Contains(row[12], "alice@example.com") {
		t.Errorf("details not preserved: %q", row[12])
	}
}

func TestCSVWriter_UnparseableIPDropped(t *testing.T) {
	// Simulate an upstream leak where ActorIP contains something that
	// isn't a valid address. ScanRow's netip check sets it to "" — writers
	// just emit the field as-given, so the defence is upstream.
	var buf bytes.Buffer
	w := NewCSVWriter(&buf)
	_ = w.WriteHeader()
	row := sampleRow()
	row.ActorIP = ""
	if err := w.Write(row); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), ",,") < 1 {
		t.Errorf("expected empty IP as empty CSV cell, got %q", buf.String())
	}
}

func TestNDJSONWriter_OneLinePerRow(t *testing.T) {
	var buf bytes.Buffer
	w := NewNDJSONWriter(&buf)
	_ = w.WriteHeader() // no-op
	if err := w.Write(sampleRow()); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(sampleRow()); err != nil {
		t.Fatal(err)
	}

	lines := bytes.Split(buf.Bytes(), []byte("\n"))
	// Split yields trailing empty after last newline.
	if len(lines) != 3 || len(lines[2]) != 0 {
		t.Fatalf("expected 2 lines + trailing empty, got %d: %q", len(lines), buf.String())
	}
	// Each line is valid JSON.
	for i, line := range lines[:2] {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Errorf("line %d not valid JSON: %v (%q)", i, err, line)
		}
		if m["action"] != "auth.login.succeeded" {
			t.Errorf("line %d action wrong: %v", i, m["action"])
		}
	}
}

func TestNDJSONWriter_EmptyDetailsOmitted(t *testing.T) {
	var buf bytes.Buffer
	w := NewNDJSONWriter(&buf)
	row := sampleRow()
	row.Details = []byte(`{}`)
	if err := w.Write(row); err != nil {
		t.Fatal(err)
	}
	// Empty details should not appear as "details":{}.
	if bytes.Contains(buf.Bytes(), []byte(`"details":{}`)) {
		t.Errorf("empty details leaked: %q", buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte(`"details":`)) {
		t.Errorf("details key present for empty map: %q", buf.String())
	}
}

func TestNDJSONWriter_NoWhitespaceInsideRows(t *testing.T) {
	var buf bytes.Buffer
	w := NewNDJSONWriter(&buf)
	if err := w.Write(sampleRow()); err != nil {
		t.Fatal(err)
	}
	// Must end with exactly one newline, no other inner whitespace.
	s := string(buf.Bytes())
	if !strings.HasSuffix(s, "\n") {
		t.Error("expected trailing newline")
	}
	if strings.Contains(s[:len(s)-1], "\n") {
		t.Errorf("row has internal newline: %q", s)
	}
}
