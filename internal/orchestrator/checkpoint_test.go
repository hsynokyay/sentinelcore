package orchestrator

import (
	"testing"
)

func TestCheckpointStore_SaveLoad(t *testing.T) {
	store := NewCheckpointStore()

	cp := &Checkpoint{
		ScanJobID:       "scan-001",
		WorkerID:        "worker-1",
		CompletedTests:  []string{"test-1", "test-2"},
		CurrentPosition: 2,
		TotalTests:      10,
		FindingsCount:   1,
	}

	store.Save(cp)

	loaded := store.Load("scan-001", "worker-1")
	if loaded == nil {
		t.Fatal("expected checkpoint to be loaded")
	}
	if loaded.CurrentPosition != 2 {
		t.Fatalf("expected position 2, got %d", loaded.CurrentPosition)
	}
	if loaded.LastUpdated.IsZero() {
		t.Fatal("expected LastUpdated to be set")
	}
}

func TestCheckpointStore_Delete(t *testing.T) {
	store := NewCheckpointStore()
	store.Save(&Checkpoint{ScanJobID: "scan-001", WorkerID: "worker-1"})
	store.Delete("scan-001", "worker-1")

	if store.Load("scan-001", "worker-1") != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestCheckpointStore_LoadMissing(t *testing.T) {
	store := NewCheckpointStore()
	if store.Load("nonexistent", "worker") != nil {
		t.Fatal("expected nil for missing checkpoint")
	}
}

func TestCheckpoint_Progress(t *testing.T) {
	tests := []struct {
		pos, total int
		want       float64
	}{
		{0, 10, 0},
		{5, 10, 50},
		{10, 10, 100},
		{0, 0, 0},
	}

	for _, tt := range tests {
		cp := &Checkpoint{CurrentPosition: tt.pos, TotalTests: tt.total}
		got := cp.Progress()
		if got != tt.want {
			t.Errorf("Progress(%d/%d) = %f, want %f", tt.pos, tt.total, got, tt.want)
		}
	}
}
