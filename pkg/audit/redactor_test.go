package audit

import (
	"strings"
	"testing"
)

func TestRedact_DropsSecretKeys(t *testing.T) {
	in := map[string]any{
		"client_secret":    "hunter2",
		"api_token":        "abc",
		"password":         "x",
		"session_key":      "y",
		"Password":         "CAPS",
		"user_email":       "alice@example.com",
		"count":            42,
	}
	out, dropped := Redact(in)

	for _, k := range []string{"client_secret", "api_token", "password", "session_key", "Password"} {
		if _, ok := out[k]; ok {
			t.Errorf("key %q should have been dropped", k)
		}
	}
	// Harmless keys preserved.
	if out["user_email"] != "alice@example.com" {
		t.Errorf("user_email mangled: %v", out["user_email"])
	}
	if out["count"] != 42 {
		t.Errorf("count mangled: %v", out["count"])
	}
	// Dropped list has all 5.
	if len(dropped) != 5 {
		t.Errorf("dropped count: got %d want 5 (%v)", len(dropped), dropped)
	}
}

func TestRedact_NestedMaps(t *testing.T) {
	in := map[string]any{
		"outer": map[string]any{
			"client_secret": "hunter2",
			"harmless":      "value",
			"deeper": map[string]any{
				"api_key": "xxx",
				"label":   "ok",
			},
		},
	}
	out, dropped := Redact(in)
	outer := out["outer"].(map[string]any)
	if _, ok := outer["client_secret"]; ok {
		t.Error("nested client_secret not dropped")
	}
	if outer["harmless"] != "value" {
		t.Error("nested harmless mangled")
	}
	deeper := outer["deeper"].(map[string]any)
	if _, ok := deeper["api_key"]; ok {
		t.Error("deeper api_key not dropped")
	}
	if deeper["label"] != "ok" {
		t.Error("deeper label mangled")
	}
	// Dropped paths include dot-notation.
	wantPaths := map[string]bool{
		"outer.client_secret":   true,
		"outer.deeper.api_key":  true,
	}
	for _, p := range dropped {
		if !wantPaths[p] {
			t.Errorf("unexpected dropped path: %q", p)
		}
		delete(wantPaths, p)
	}
	if len(wantPaths) > 0 {
		t.Errorf("missing dropped paths: %v", wantPaths)
	}
}

func TestRedact_TruncatesLongStrings(t *testing.T) {
	long := strings.Repeat("x", 600)
	in := map[string]any{"payload": long, "short": "ok"}
	out, _ := Redact(in)
	got := out["payload"].(string)
	if len(got) != truncateLimit+len(truncateSuffix) {
		t.Errorf("truncation wrong length: got %d want %d",
			len(got), truncateLimit+len(truncateSuffix))
	}
	if !strings.HasSuffix(got, truncateSuffix) {
		t.Errorf("expected suffix %q, got tail %q", truncateSuffix, got[len(got)-10:])
	}
	if out["short"] != "ok" {
		t.Error("short string mangled")
	}
}

func TestRedact_ArraysOfMaps(t *testing.T) {
	in := map[string]any{
		"items": []any{
			map[string]any{"secret": "x", "name": "a"},
			map[string]any{"api_key": "y", "name": "b"},
		},
	}
	out, dropped := Redact(in)
	items := out["items"].([]any)
	a := items[0].(map[string]any)
	b := items[1].(map[string]any)
	if _, ok := a["secret"]; ok {
		t.Error("arr[0].secret not dropped")
	}
	if _, ok := b["api_key"]; ok {
		t.Error("arr[1].api_key not dropped")
	}
	if a["name"] != "a" || b["name"] != "b" {
		t.Error("array name fields mangled")
	}
	if len(dropped) != 2 {
		t.Errorf("want 2 dropped, got %d: %v", len(dropped), dropped)
	}
}

func TestRedact_NilInput(t *testing.T) {
	out, dropped := Redact(nil)
	if out != nil {
		t.Errorf("nil input should return nil, got %v", out)
	}
	if len(dropped) != 0 {
		t.Errorf("nil input should return no drops, got %v", dropped)
	}
}

func TestRedact_LeavesNonSecretIntact(t *testing.T) {
	// Values that LOOK like secrets but have innocent keys must be preserved.
	in := map[string]any{
		"email":      "abc@def.com",
		"user_id":    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		"ip_address": "10.0.0.1",
		"count":      42,
		"active":     true,
	}
	out, dropped := Redact(in)
	if len(dropped) != 0 {
		t.Errorf("no drops expected, got %v", dropped)
	}
	if len(out) != len(in) {
		t.Errorf("size mismatch: got %d want %d", len(out), len(in))
	}
}
