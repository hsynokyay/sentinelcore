package policy

import (
	"testing"
)

func TestCache_CanFalseBeforeLoad(t *testing.T) {
	c := NewCache()
	if c.Can("owner", "risks.read") {
		t.Fatal("expected false before Reload")
	}
}
