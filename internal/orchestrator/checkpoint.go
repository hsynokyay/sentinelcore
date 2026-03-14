package orchestrator

import (
	"encoding/json"
	"sync"
	"time"
)

// Checkpoint represents a scan progress checkpoint for crash recovery.
type Checkpoint struct {
	ScanJobID       string          `json:"scan_job_id"`
	WorkerID        string          `json:"worker_id"`
	CompletedTests  []string        `json:"completed_tests"`
	CurrentPosition int             `json:"current_position"`
	TotalTests      int             `json:"total_tests"`
	FindingsCount   int             `json:"findings_count"`
	LastUpdated     time.Time       `json:"last_updated"`
	Extra           json.RawMessage `json:"extra,omitempty"`
}

// CheckpointStore manages scan checkpoints for resume-on-crash.
// In production, this is backed by the scans.scan_checkpoints table.
type CheckpointStore struct {
	mu          sync.RWMutex
	checkpoints map[string]*Checkpoint // scanJobID:workerID → checkpoint
}

// NewCheckpointStore creates an in-memory checkpoint store.
func NewCheckpointStore() *CheckpointStore {
	return &CheckpointStore{
		checkpoints: make(map[string]*Checkpoint),
	}
}

func key(scanJobID, workerID string) string {
	return scanJobID + ":" + workerID
}

// Save stores or updates a checkpoint.
func (s *CheckpointStore) Save(cp *Checkpoint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp.LastUpdated = time.Now()
	s.checkpoints[key(cp.ScanJobID, cp.WorkerID)] = cp
}

// Load retrieves the latest checkpoint for a scan+worker pair.
func (s *CheckpointStore) Load(scanJobID, workerID string) *Checkpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.checkpoints[key(scanJobID, workerID)]
}

// Delete removes a checkpoint after successful scan completion.
func (s *CheckpointStore) Delete(scanJobID, workerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.checkpoints, key(scanJobID, workerID))
}

// Progress returns the completion percentage of a checkpoint.
func (cp *Checkpoint) Progress() float64 {
	if cp.TotalTests == 0 {
		return 0
	}
	return float64(cp.CurrentPosition) / float64(cp.TotalTests) * 100
}
