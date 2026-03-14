package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	pkgaudit "github.com/sentinelcore/sentinelcore/pkg/audit"
)

// Consumer subscribes to audit events from NATS JetStream and writes them
// to PostgreSQL in batches via the Writer.
type Consumer struct {
	js            jetstream.JetStream
	writer        *Writer
	logger        zerolog.Logger
	batchSize     int
	flushInterval time.Duration
}

// NewConsumer creates a Consumer that reads from JetStream and writes via writer.
func NewConsumer(js jetstream.JetStream, writer *Writer, logger zerolog.Logger) *Consumer {
	return &Consumer{
		js:            js,
		writer:        writer,
		logger:        logger,
		batchSize:     100,
		flushInterval: time.Second,
	}
}

// Start begins consuming audit events. It blocks until ctx is cancelled.
func (c *Consumer) Start(ctx context.Context) error {
	// Create durable consumer on AUDIT stream, subject "audit.events"
	cons, err := c.js.CreateOrUpdateConsumer(ctx, "AUDIT", jetstream.ConsumerConfig{
		Durable:       "audit-service",
		FilterSubject: "audit.events",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return err
	}

	// Consume messages in batches
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msgs, err := cons.Fetch(c.batchSize, jetstream.FetchMaxWait(c.flushInterval))
		if err != nil {
			c.logger.Warn().Err(err).Msg("fetch error")
			time.Sleep(time.Second)
			continue
		}

		var events []pkgaudit.AuditEvent
		var acks []jetstream.Msg
		for msg := range msgs.Messages() {
			var event pkgaudit.AuditEvent
			if err := json.Unmarshal(msg.Data(), &event); err != nil {
				c.logger.Error().Err(err).Msg("failed to unmarshal audit event")
				msg.Ack() // ack bad messages to avoid redelivery loop
				continue
			}
			events = append(events, event)
			acks = append(acks, msg)
		}

		if len(events) > 0 {
			if err := c.writer.WriteBatch(ctx, events); err != nil {
				c.logger.Error().Err(err).Int("count", len(events)).Msg("failed to write batch")
				// Don't ack — messages will be redelivered
				continue
			}
			for _, msg := range acks {
				msg.Ack()
			}
			c.logger.Info().Int("count", len(events)).Msg("wrote audit events")
		}
	}
}
