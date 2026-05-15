package apikeys

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// StartSessionRevokeListener listens on pg channel user_sessions_revoke.
// Payload is a user UUID. On each notification, removes all JTIs for
// that user from the Redis session store. Reconnects with exponential
// backoff if the connection drops.
//
// The trigger from migration 028 fires `NOTIFY user_sessions_revoke`
// with the user_id as payload whenever a user's role is downgraded so
// that in-flight JWT sessions are invalidated immediately.
func StartSessionRevokeListener(ctx context.Context, pool *pgxpool.Pool, sessions *auth.SessionStore, logger zerolog.Logger) {
	go func() {
		delay := time.Second
		for ctx.Err() == nil {
			if err := listenOnce(ctx, pool, sessions, logger); err != nil {
				logger.Warn().
					Err(err).
					Dur("delay", delay).
					Msg("session revoke listener lost, reconnecting")
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				if delay < 30*time.Second {
					delay *= 2
				}
				continue
			}
			delay = time.Second
		}
	}()
}

func listenOnce(ctx context.Context, pool *pgxpool.Pool, sessions *auth.SessionStore, logger zerolog.Logger) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN user_sessions_revoke"); err != nil {
		return err
	}
	logger.Info().Msg("session revoke listener started")

	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		userID := n.Payload
		if userID == "" {
			continue
		}
		if err := sessions.RevokeAllForUser(ctx, userID); err != nil {
			logger.Warn().Err(err).Str("user_id", userID).Msg("revoke user sessions failed")
			continue
		}
		logger.Info().Str("user_id", userID).Msg("user sessions revoked on role change")
	}
}
