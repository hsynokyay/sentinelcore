package correlation

import (
	"context"
	"sync"

	corr "github.com/sentinelcore/sentinelcore/pkg/correlation"
)

// MemStore is an in-memory FindingStore for testing.
type MemStore struct {
	mu        sync.RWMutex
	findings  map[string]*corr.RawFinding // fingerprint → finding
	groups    []*corr.CorrelationGroup
	runs      []*corr.CorrelationRun
}

// NewMemStore creates an in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		findings: make(map[string]*corr.RawFinding),
	}
}

func (s *MemStore) LoadProjectFindings(_ context.Context, projectID string) ([]*corr.RawFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*corr.RawFinding
	for _, f := range s.findings {
		if f.ProjectID == projectID {
			results = append(results, f)
		}
	}
	return results, nil
}

func (s *MemStore) UpsertFinding(_ context.Context, f *corr.RawFinding) (string, bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.findings[f.Fingerprint]
	if ok {
		// Existing: update last_seen, scan_count
		existing.FoundAt = f.FoundAt
		return existing.ID, false, 2, nil // simplified scan_count
	}

	// New finding
	s.findings[f.Fingerprint] = f
	return f.ID, true, 1, nil
}

func (s *MemStore) SaveCorrelationGroup(_ context.Context, group *corr.CorrelationGroup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups = append(s.groups, group)
	return nil
}

func (s *MemStore) SaveCorrelationRun(_ context.Context, run *corr.CorrelationRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs = append(s.runs, run)
	return nil
}

// Groups returns all saved correlation groups (for test assertions).
func (s *MemStore) Groups() []*corr.CorrelationGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*corr.CorrelationGroup, len(s.groups))
	copy(out, s.groups)
	return out
}

// Runs returns all saved correlation runs (for test assertions).
func (s *MemStore) Runs() []*corr.CorrelationRun {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*corr.CorrelationRun, len(s.runs))
	copy(out, s.runs)
	return out
}

// FindingCount returns the number of stored findings.
func (s *MemStore) FindingCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.findings)
}
