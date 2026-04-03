package browser

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestPersistInventory_NilPool(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")
	inv.AddEntry(&SurfaceEntry{
		ID: "test-1", Type: SurfaceRoute, URL: "https://example.com/",
		Method: "GET", FirstSeenAt: time.Now(), LastSeenAt: time.Now(),
	})

	err := PersistInventory(context.Background(), nil, inv, zerolog.Nop())
	if err == nil {
		t.Error("expected error for nil pool")
	}
}

func TestPersistInventory_EmptyInventory(t *testing.T) {
	inv := NewSurfaceInventory("proj-1", "scan-1")

	// Should return nil (no-op) for empty inventory even with nil pool
	err := PersistInventory(context.Background(), nil, inv, zerolog.Nop())
	if err != nil {
		t.Errorf("empty inventory should be a no-op, got error: %v", err)
	}
}

func TestPersistInventory_NilInventory(t *testing.T) {
	err := PersistInventory(context.Background(), nil, nil, zerolog.Nop())
	if err != nil {
		t.Errorf("nil inventory should be a no-op, got error: %v", err)
	}
}
