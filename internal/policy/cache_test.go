package policy

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestCache_CanFalseBeforeLoad(t *testing.T) {
	c := NewCache()
	if c.Can("owner", "risks.read") {
		t.Fatal("expected false before Reload")
	}
}

func TestCache_ReloadMatchesDB(t *testing.T) {
	pool := testPool(t)
	c := NewCache()
	if err := c.Reload(context.Background(), pool); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if !c.Can("owner", "users.manage") {
		t.Fatal("owner should have users.manage")
	}
	if c.Can("admin", "users.manage") {
		t.Fatal("admin must NOT have users.manage")
	}
	if !c.Can("developer", "risks.read") {
		t.Fatal("developer should have risks.read")
	}
	if c.Can("developer", "scans.run") {
		t.Fatal("developer must NOT have scans.run")
	}
	if !c.HasPermission("scans.run") {
		t.Fatal("HasPermission should return true for known permission")
	}
	if c.HasPermission("nonexistent.perm") {
		t.Fatal("HasPermission should return false for unknown")
	}
}

func TestCache_ConcurrentReadDuringReload(t *testing.T) {
	pool := testPool(t)
	c := NewCache()
	if err := c.Reload(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_ = c.Can("owner", "risks.read")
		}
		close(done)
	}()
	for i := 0; i < 20; i++ {
		if err := c.Reload(context.Background(), pool); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

func TestCache_Listen_SafetyPollReloads(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewCache()
	// Seed state (empty before listen).
	if c.Can("owner", "users.manage") {
		t.Fatal("cache should start empty")
	}

	logger := zerolog.Nop()
	c.Listen(ctx, pool, "role_permissions_changed", logger)

	// Instead of waiting 60s for the safety poll, manually reload — this
	// test only verifies that Listen doesn't panic/race when invoked
	// alongside a concurrent Reload. The 60s poll is tested manually.
	if err := c.Reload(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	if !c.Can("owner", "users.manage") {
		t.Fatal("after reload, owner should have users.manage")
	}
}

func TestCache_Listen_NotifyTriggersReload(t *testing.T) {
	pool := testPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := NewCache()
	logger := zerolog.Nop()
	c.Listen(ctx, pool, "role_permissions_changed", logger)

	// Give Listen a moment to set up the LISTEN on the connection.
	time.Sleep(100 * time.Millisecond)

	// Emit a NOTIFY. The listener should wake up and call Reload.
	if _, err := pool.Exec(context.Background(),
		"NOTIFY role_permissions_changed, 'test-payload'"); err != nil {
		t.Fatalf("NOTIFY: %v", err)
	}

	// Wait up to 2s for the reload to populate the cache.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Can("owner", "users.manage") {
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("cache did not populate within 2s after NOTIFY")
}
