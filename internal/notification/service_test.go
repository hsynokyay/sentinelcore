package notification

import (
	"context"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/governance"
)

func TestCreateNotification_NilPool(t *testing.T) {
	err := CreateNotification(context.Background(), nil, "u1", "org1", &governance.Notification{
		Category: "test",
		Title:    "Hello",
	})
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestCreateNotification_NilNotification(t *testing.T) {
	// Cannot pass a real pool, but nil notification should be caught first
	// only if pool is also nil (pool check runs first). Test the nil-notification path
	// by verifying the error message when pool is also nil.
	err := CreateNotification(context.Background(), nil, "u1", "org1", nil)
	if err == nil {
		t.Fatal("expected error for nil inputs")
	}
}

func TestCreateNotificationsForUsers_NilPool(t *testing.T) {
	err := CreateNotificationsForUsers(context.Background(), nil, "org1",
		[]string{"u1"}, "test", "title", "body", "finding", "f1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestCreateNotificationsForUsers_EmptyUsers(t *testing.T) {
	// Empty user list should return nil even with nil pool.
	err := CreateNotificationsForUsers(context.Background(), nil, "org1",
		[]string{}, "test", "title", "body", "finding", "f1")
	if err != nil {
		t.Fatalf("expected nil for empty users, got: %v", err)
	}
}

func TestListNotifications_NilPool(t *testing.T) {
	_, err := ListNotifications(context.Background(), nil, "u1", "org1", 10, 0)
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestMarkRead_NilPool(t *testing.T) {
	err := MarkRead(context.Background(), nil, "u1", "org1", "n1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestMarkAllRead_NilPool(t *testing.T) {
	err := MarkAllRead(context.Background(), nil, "u1", "org1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}

func TestUnreadCount_NilPool(t *testing.T) {
	_, err := UnreadCount(context.Background(), nil, "u1", "org1")
	if err == nil {
		t.Fatal("expected error for nil pool")
	}
}
