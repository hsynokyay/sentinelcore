// Package replay provides the action-list replayer used by
// RecordedLoginStrategy to refresh sessions for automatable bundles.
package replay

import (
	"fmt"
	"sync"
	"time"
)

type RateLimit struct {
	mu       sync.Mutex
	last     map[string]time.Time
	interval time.Duration
}

func NewRateLimit() *RateLimit {
	return &RateLimit{
		last:     make(map[string]time.Time),
		interval: time.Minute,
	}
}

func (r *RateLimit) Allow(bundleID, host string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := bundleID + "|" + host
	now := time.Now()
	if last, ok := r.last[key]; ok {
		if now.Sub(last) < r.interval {
			return fmt.Errorf("replay: rate-limited (last replay %s ago)", now.Sub(last).Round(time.Second))
		}
	}
	r.last[key] = now
	return nil
}

func (r *RateLimit) SetInterval(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.interval = d
}
