package bundles

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAction_JSONRoundTrip(t *testing.T) {
	a := Action{Kind: ActionNavigate, URL: "https://app/login", Timestamp: time.Now().UTC()}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back Action
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Kind != ActionNavigate || back.URL != a.URL {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}

func TestActionKind_Values(t *testing.T) {
	if ActionNavigate != "navigate" {
		t.Error("navigate")
	}
	if ActionClick != "click" {
		t.Error("click")
	}
	if ActionWaitForLoad != "wait_for_load" {
		t.Error("wait_for_load")
	}
	if ActionCaptchaMark != "captcha_mark" {
		t.Error("captcha_mark")
	}
}
