package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/notification"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("service", "notification-worker").Logger()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Connect to PostgreSQL
	pool, err := pgxpool.New(ctx, getEnv("DATABASE_URL", "postgres://sentinel:sentinel@localhost:5432/sentinel?sslmode=disable"))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()

	// Connect to NATS
	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to connect to NATS")
	}
	defer nc.Close()

	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("failed to ensure NATS streams")
	}

	// Subscribe to governance.notifications for in-app notification fan-out
	go consumeNotificationEvents(ctx, js, pool, &logger)

	// Webhook delivery loop
	go deliveryLoop(ctx, pool, &logger)

	logger.Info().Msg("notification worker started")
	<-ctx.Done()
	logger.Info().Msg("notification worker shutting down")
}

func consumeNotificationEvents(ctx context.Context, js jetstream.JetStream, pool *pgxpool.Pool, logger *zerolog.Logger) {
	consumer, err := js.CreateOrUpdateConsumer(ctx, "GOVERNANCE", jetstream.ConsumerConfig{
		Durable:       "notification-worker",
		FilterSubject: "governance.notifications",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		logger.Error().Err(err).Msg("failed to create consumer")
		return
	}

	for {
		msgs, err := consumer.Fetch(10, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		for msg := range msgs.Messages() {
			processNotificationEvent(ctx, msg, pool, logger)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func processNotificationEvent(ctx context.Context, msg jetstream.Msg, pool *pgxpool.Pool, logger *zerolog.Logger) {
	var event notification.NotificationEvent
	if err := json.Unmarshal(msg.Data(), &event); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal notification event")
		msg.Ack()
		return
	}

	// Create in-app notifications for all recipients
	if len(event.Recipients) > 0 {
		title := event.Data["title"]
		if title == "" {
			title = event.EventType
		}
		body := event.Data["body"]

		err := notification.CreateNotificationsForUsers(ctx, pool, event.OrgID,
			event.Recipients, event.EventType, title, body,
			event.ResourceType, event.ResourceID)
		if err != nil {
			logger.Error().Err(err).Str("event_type", event.EventType).Msg("failed to create notifications")
		}
	}

	msg.Ack()
	logger.Info().Str("event_type", event.EventType).Int("recipients", len(event.Recipients)).Msg("processed notification event")
}

func deliveryLoop(ctx context.Context, pool *pgxpool.Pool, logger *zerolog.Logger) {
	intervalStr := getEnv("WEBHOOK_DELIVERY_INTERVAL", "30")
	intervalSec, _ := strconv.Atoi(intervalStr)
	if intervalSec <= 0 {
		intervalSec = 30
	}
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deliverPendingWebhooks(ctx, pool, logger)
		}
	}
}

func deliverPendingWebhooks(ctx context.Context, pool *pgxpool.Pool, logger *zerolog.Logger) {
	pending, err := notification.GetPendingDeliveries(ctx, pool, 50)
	if err != nil {
		logger.Error().Err(err).Msg("failed to get pending deliveries")
		return
	}

	for _, attempt := range pending {
		// Look up webhook config for this delivery
		// In production this would query the DB; for now we log and mark exhausted after max retries
		if attempt.Attempts >= notification.MaxRetries {
			attempt.Status = "exhausted"
			if err := notification.RecordDeliveryAttempt(ctx, pool, &attempt); err != nil {
				logger.Error().Err(err).Str("delivery_id", attempt.ID).Msg("failed to update exhausted delivery")
			}
			continue
		}

		logger.Info().
			Str("delivery_id", attempt.ID).
			Str("webhook_id", attempt.WebhookID).
			Int("attempt", attempt.Attempts+1).
			Msg("delivering webhook")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
