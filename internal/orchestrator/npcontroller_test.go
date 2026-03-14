package orchestrator

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestNPController_CreateDelete(t *testing.T) {
	applier := NewInMemoryApplier()
	ctrl := NewNPController(NPControllerConfig{
		Namespace:  "sentinelcore",
		DefaultTTL: time.Hour,
	}, applier, zerolog.Nop())

	ctx := context.Background()
	ips := []net.IP{net.ParseIP("93.184.216.34")}

	// Create
	err := ctrl.CreatePolicy(ctx, "scan-0001-abcd", "worker-pod-1", ips)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if ctrl.ActivePolicies() != 1 {
		t.Fatalf("expected 1 active policy, got %d", ctrl.ActivePolicies())
	}
	if len(applier.Applied) != 1 {
		t.Fatal("expected policy to be applied")
	}

	// Duplicate
	err = ctrl.CreatePolicy(ctx, "scan-0001-abcd", "worker-pod-1", ips)
	if err == nil {
		t.Fatal("expected error for duplicate policy")
	}

	// Delete
	err = ctrl.DeletePolicy(ctx, "scan-0001-abcd")
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if ctrl.ActivePolicies() != 0 {
		t.Fatal("expected 0 active policies after delete")
	}
}

func TestNPController_GarbageCollect(t *testing.T) {
	applier := NewInMemoryApplier()
	ctrl := NewNPController(NPControllerConfig{
		Namespace:  "sentinelcore",
		DefaultTTL: -time.Second, // already expired
	}, applier, zerolog.Nop())

	ctx := context.Background()
	ips := []net.IP{net.ParseIP("1.2.3.4")}

	ctrl.CreatePolicy(ctx, "scan-expired", "worker-1", ips)
	if ctrl.ActivePolicies() != 1 {
		t.Fatal("expected 1 policy before GC")
	}

	collected := ctrl.GarbageCollect(ctx)
	if collected != 1 {
		t.Fatalf("expected 1 collected, got %d", collected)
	}
	if ctrl.ActivePolicies() != 0 {
		t.Fatal("expected 0 policies after GC")
	}
}

func TestNPController_IPv6(t *testing.T) {
	applier := NewInMemoryApplier()
	ctrl := NewNPController(NPControllerConfig{
		Namespace: "sentinelcore",
	}, applier, zerolog.Nop())

	ctx := context.Background()
	ips := []net.IP{net.ParseIP("2001:db8::1")}

	err := ctrl.CreatePolicy(ctx, "scan-ipv6", "worker-1", ips)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	policy := applier.Applied["dast-sco"]
	// Check that at least one policy exists with IPv6 CIDR
	for _, p := range applier.Applied {
		for _, cidr := range p.AllowedCIDRs {
			if cidr == "2001:db8::1/128" {
				return // success
			}
		}
		_ = p
	}
	_ = policy
	t.Fatal("expected IPv6 /128 CIDR in policy")
}
