package recording

import (
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

func TestParseAndValidate_Click(t *testing.T) {
	a, err := ParseAndValidate(`{"kind":"click","selector":"#login","t":1700000000000}`)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if a.Kind != bundles.ActionClick {
		t.Fatalf("kind=%v", a.Kind)
	}
	if a.Selector != "#login" {
		t.Fatalf("selector=%q", a.Selector)
	}
}

func TestParseAndValidate_Fill(t *testing.T) {
	a, err := ParseAndValidate(`{"kind":"fill","selector":"input[name=\"user\"]","t":1700000000000}`)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if a.Kind != bundles.ActionFill {
		t.Fatalf("kind=%v", a.Kind)
	}
}

func TestParseAndValidate_FillRejectsValue(t *testing.T) {
	_, err := ParseAndValidate(`{"kind":"fill","selector":"#pwd","t":1,"value":"secret"}`)
	if err == nil || !strings.Contains(err.Error(), "must not carry value") {
		t.Fatalf("expected value rejection, got %v", err)
	}
}

func TestParseAndValidate_SelectorTooLong(t *testing.T) {
	long := strings.Repeat("a", 257)
	_, err := ParseAndValidate(`{"kind":"click","selector":"` + long + `","t":1}`)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected length rejection, got %v", err)
	}
}

func TestParseAndValidate_SelectorBadChars(t *testing.T) {
	_, err := ParseAndValidate(`{"kind":"click","selector":"a\nb","t":1}`)
	if err == nil || !strings.Contains(err.Error(), "invalid characters") {
		t.Fatalf("expected charset rejection, got %v", err)
	}
}

func TestParseAndValidate_BadKind(t *testing.T) {
	_, err := ParseAndValidate(`{"kind":"navigate","t":1}`)
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("expected unknown kind, got %v", err)
	}
}

func TestParseAndValidate_BadJSON(t *testing.T) {
	_, err := ParseAndValidate(`{not json`)
	if err == nil {
		t.Fatal("expected JSON error")
	}
}

func TestCaptureScript_NotEmpty(t *testing.T) {
	if len(CaptureScript()) < 200 {
		t.Fatalf("capture script too short: %d bytes", len(CaptureScript()))
	}
	if !strings.Contains(CaptureScript(), "__sentinel_emit") {
		t.Fatal("capture script must reference __sentinel_emit binding")
	}
	if strings.Contains(CaptureScript(), ".value") || strings.Contains(CaptureScript(), "value:") {
		// Defense-in-depth: the script must never read or emit element values.
		t.Fatal("capture script must not reference .value")
	}
}
