package notification

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sentinelcore/sentinelcore/internal/governance"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

// CreateNotification inserts a single in-app notification with RLS enforcement.
func CreateNotification(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, n *governance.Notification) error {
	if pool == nil {
		return errors.New("notification: pool is nil")
	}
	if n == nil {
		return errors.New("notification: notification is nil")
	}

	if n.ID == "" {
		n.ID = uuid.New().String()
	}
	n.OrgID = orgID
	n.UserID = userID
	n.Read = false
	n.CreatedAt = time.Now()

	return db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		_, err := conn.Exec(ctx, `
			INSERT INTO governance.notifications (
				id, org_id, user_id, category, title, body,
				resource_type, resource_id, read, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			n.ID, n.OrgID, n.UserID, n.Category, n.Title, n.Body,
			n.ResourceType, n.ResourceID, n.Read, n.CreatedAt,
		)
		return err
	})
}

// CreateNotificationsForUsers inserts notifications for multiple users in a batch.
// This operates without RLS and is intended for the notification worker.
func CreateNotificationsForUsers(ctx context.Context, pool *pgxpool.Pool, orgID string, userIDs []string, category, title, body, resourceType, resourceID string) error {
	if len(userIDs) == 0 {
		return nil
	}
	if pool == nil {
		return errors.New("notification: pool is nil")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	now := time.Now()
	for _, uid := range userIDs {
		id := uuid.New().String()
		_, err := conn.Exec(ctx, `
			INSERT INTO governance.notifications (
				id, org_id, user_id, category, title, body,
				resource_type, resource_id, read, created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			id, orgID, uid, category, title, body,
			resourceType, resourceID, false, now,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// ListNotifications returns paged notifications for a user, newest first.
func ListNotifications(ctx context.Context, pool *pgxpool.Pool, userID, orgID string, limit, offset int) ([]governance.Notification, error) {
	if pool == nil {
		return nil, errors.New("notification: pool is nil")
	}
	if limit <= 0 {
		limit = 50
	}

	var results []governance.Notification
	err := db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		rows, err := conn.Query(ctx, `
			SELECT id, org_id, user_id, category, title, body,
			       resource_type, resource_id, read, created_at
			  FROM governance.notifications
			 WHERE user_id = $1
			 ORDER BY created_at DESC
			 LIMIT $2 OFFSET $3`, userID, limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var n governance.Notification
			if scanErr := rows.Scan(
				&n.ID, &n.OrgID, &n.UserID, &n.Category, &n.Title, &n.Body,
				&n.ResourceType, &n.ResourceID, &n.Read, &n.CreatedAt,
			); scanErr != nil {
				return scanErr
			}
			results = append(results, n)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

// MarkRead marks a single notification as read.
func MarkRead(ctx context.Context, pool *pgxpool.Pool, userID, orgID, notificationID string) error {
	if pool == nil {
		return errors.New("notification: pool is nil")
	}

	return db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		_, err := conn.Exec(ctx, `
			UPDATE governance.notifications
			   SET read = true
			 WHERE id = $1 AND user_id = $2`, notificationID, userID)
		return err
	})
}

// MarkAllRead marks all of a user's notifications as read.
func MarkAllRead(ctx context.Context, pool *pgxpool.Pool, userID, orgID string) error {
	if pool == nil {
		return errors.New("notification: pool is nil")
	}

	return db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		_, err := conn.Exec(ctx, `
			UPDATE governance.notifications
			   SET read = true
			 WHERE user_id = $1 AND read = false`, userID)
		return err
	})
}

// UnreadCount returns the number of unread notifications for a user.
func UnreadCount(ctx context.Context, pool *pgxpool.Pool, userID, orgID string) (int, error) {
	if pool == nil {
		return 0, errors.New("notification: pool is nil")
	}

	var count int
	err := db.WithRLS(ctx, pool, userID, orgID, func(ctx context.Context, conn *pgxpool.Conn) error {
		row := conn.QueryRow(ctx, `
			SELECT COUNT(*)
			  FROM governance.notifications
			 WHERE user_id = $1 AND read = false`, userID)
		return row.Scan(&count)
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
