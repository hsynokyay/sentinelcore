// Package orchestrator implements DAST scan orchestration including
// dynamic NetworkPolicy management and DNS pinning.
package orchestrator

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// NetworkPolicy represents a Kubernetes NetworkPolicy for DAST worker isolation.
type NetworkPolicy struct {
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	ScanJobID   string    `json:"scan_job_id"`
	WorkerPod   string    `json:"worker_pod"`
	AllowedCIDRs []string `json:"allowed_cidrs"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// NPControllerConfig configures the NetworkPolicy controller.
type NPControllerConfig struct {
	Namespace    string
	DefaultTTL   time.Duration
	GCInterval   time.Duration
}

// NPController manages dynamic NetworkPolicies for DAST scan workers.
// In production, this would use the Kubernetes API. This implementation
// provides the logic layer that the K8s adapter wraps.
type NPController struct {
	mu       sync.RWMutex
	policies map[string]*NetworkPolicy // scanJobID → policy
	cfg      NPControllerConfig
	logger   zerolog.Logger
	// applier would be a K8s client interface in production
	applier  PolicyApplier
}

// PolicyApplier abstracts Kubernetes API calls for testing.
type PolicyApplier interface {
	Apply(ctx context.Context, policy *NetworkPolicy) error
	Delete(ctx context.Context, name, namespace string) error
}

// InMemoryApplier is a test implementation of PolicyApplier.
type InMemoryApplier struct {
	mu      sync.Mutex
	Applied map[string]*NetworkPolicy
}

func NewInMemoryApplier() *InMemoryApplier {
	return &InMemoryApplier{Applied: make(map[string]*NetworkPolicy)}
}

func (a *InMemoryApplier) Apply(_ context.Context, policy *NetworkPolicy) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Applied[policy.Name] = policy
	return nil
}

func (a *InMemoryApplier) Delete(_ context.Context, name, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.Applied, name)
	return nil
}

// NewNPController creates a NetworkPolicy controller.
func NewNPController(cfg NPControllerConfig, applier PolicyApplier, logger zerolog.Logger) *NPController {
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 2 * time.Hour
	}
	if cfg.GCInterval == 0 {
		cfg.GCInterval = 5 * time.Minute
	}

	return &NPController{
		policies: make(map[string]*NetworkPolicy),
		cfg:      cfg,
		applier:  applier,
		logger:   logger.With().Str("component", "np-controller").Logger(),
	}
}

// CreatePolicy creates and applies a NetworkPolicy restricting a DAST worker
// to only communicate with the pinned target IPs and control plane.
func (c *NPController) CreatePolicy(ctx context.Context, scanJobID, workerPod string, pinnedIPs []net.IP) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.policies[scanJobID]; exists {
		return fmt.Errorf("policy already exists for scan %s", scanJobID)
	}

	var cidrs []string
	for _, ip := range pinnedIPs {
		if ip.To4() != nil {
			cidrs = append(cidrs, ip.String()+"/32")
		} else {
			cidrs = append(cidrs, ip.String()+"/128")
		}
	}

	policy := &NetworkPolicy{
		Name:         fmt.Sprintf("dast-scope-%s", scanJobID),
		Namespace:    c.cfg.Namespace,
		ScanJobID:    scanJobID,
		WorkerPod:    workerPod,
		AllowedCIDRs: cidrs,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(c.cfg.DefaultTTL),
	}

	if err := c.applier.Apply(ctx, policy); err != nil {
		return fmt.Errorf("failed to apply network policy: %w", err)
	}

	c.policies[scanJobID] = policy
	c.logger.Info().
		Str("scan_job_id", scanJobID).
		Str("policy_name", policy.Name).
		Int("allowed_cidrs", len(cidrs)).
		Msg("network policy created")

	return nil
}

// DeletePolicy removes the NetworkPolicy for a completed scan.
func (c *NPController) DeletePolicy(ctx context.Context, scanJobID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	policy, ok := c.policies[scanJobID]
	if !ok {
		return nil // already cleaned up
	}

	if err := c.applier.Delete(ctx, policy.Name, policy.Namespace); err != nil {
		return fmt.Errorf("failed to delete network policy: %w", err)
	}

	delete(c.policies, scanJobID)
	c.logger.Info().
		Str("scan_job_id", scanJobID).
		Str("policy_name", policy.Name).
		Msg("network policy deleted")

	return nil
}

// GarbageCollect removes expired NetworkPolicies.
// Collects expired entries under lock, then deletes outside the lock
// to avoid blocking Create/Delete during K8s API calls.
func (c *NPController) GarbageCollect(ctx context.Context) int {
	// Phase 1: identify expired policies under read lock
	c.mu.RLock()
	now := time.Now()
	type expired struct {
		scanJobID string
		policy    *NetworkPolicy
	}
	var toDelete []expired
	for scanJobID, policy := range c.policies {
		if now.After(policy.ExpiresAt) {
			toDelete = append(toDelete, expired{scanJobID, policy})
		}
	}
	c.mu.RUnlock()

	if len(toDelete) == 0 {
		return 0
	}

	// Phase 2: delete from K8s without holding the lock
	count := 0
	var deleted []string
	for _, e := range toDelete {
		if err := c.applier.Delete(ctx, e.policy.Name, e.policy.Namespace); err != nil {
			c.logger.Error().Err(err).
				Str("policy_name", e.policy.Name).
				Msg("failed to GC network policy")
			continue
		}
		deleted = append(deleted, e.scanJobID)
		count++
		c.logger.Info().
			Str("policy_name", e.policy.Name).
			Str("scan_job_id", e.scanJobID).
			Msg("garbage collected expired network policy")
	}

	// Phase 3: remove from map under write lock
	if len(deleted) > 0 {
		c.mu.Lock()
		for _, id := range deleted {
			delete(c.policies, id)
		}
		c.mu.Unlock()
	}

	return count
}

// RunGC starts a background goroutine that periodically garbage collects policies.
func (c *NPController) RunGC(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.GCInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collected := c.GarbageCollect(ctx)
			if collected > 0 {
				c.logger.Info().Int("collected", collected).Msg("GC cycle completed")
			}
		}
	}
}

// ActivePolicies returns the count of active policies.
func (c *NPController) ActivePolicies() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.policies)
}
