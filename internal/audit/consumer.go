package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	pkgaudit "github.com/sentinelcore/sentinelcore/pkg/audit"
)

// Consumer subscribes to audit events from NATS JetStream and persists them.
//
// It has TWO write paths, picked at construction time via hmacWriter != nil:
//
//   - LEGACY (hmacWriter == nil): writes previous_hash='' / entry_hash=''
//     through Writer.WriteBatch. This is what existed pre-Phase-6 and what
//     the verifier flags as 'partial' outcome.
//
//   - HMAC-aware (hmacWriter != nil): writes one row at a time through
//     HMACWriter.WriteOne, which computes the chain under a per-partition
//     advisory lock and is idempotent on the (event_id, timestamp) unique
//     index. Used in the Phase 6 Chunk 5 cut-over.
//
// Shadow mode (Chunk 4): hmacWriter set, legacy writer also present,
// AUDIT_CONSUMER_MODE=hmac activates the chained path. Default remains
// legacy so a broken key resolver doesn't halt the audit pipeline.
type Consumer struct {
	js            jetstream.JetStream
	writer        *Writer
	hmacWriter    *HMACWriter
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

// WithHMACWriter enables the chained write path. When set the consumer
// bypasses WriteBatch and calls HMACWriter.WriteOne per event.
func (c *Consumer) WithHMACWriter(w *HMACWriter) *Consumer {
	c.hmacWriter = w
	return c
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

		if len(events) == 0 {
			continue
		}

		if c.hmacWriter != nil {
			// HMAC-chained path: per-event, idempotent. Acks are per-event
			// so a transient failure on event N doesn't stall events 0..N-1.
			var wrote, dups int
			for i, e := range events {
				dup, err := c.hmacWriter.WriteOne(ctx, e)
				if err != nil {
					c.logger.Error().Err(err).Str("event_id", e.EventID).Msg("hmac write failed")
					// Nak remaining via timeout; ack only what we've written.
					break
				}
				if dup {
					dups++
				} else {
					wrote++
				}
				acks[i].Ack()
			}
			c.logger.Info().Int("wrote", wrote).Int("duplicates", dups).
				Int("total", len(events)).Msg("audit events (hmac)")
			continue
		}

		// Legacy batch path.
		if err := c.writer.WriteBatch(ctx, events); err != nil {
			c.logger.Error().Err(err).Int("count", len(events)).Msg("failed to write batch")
			continue
		}
		for _, msg := range acks {
			msg.Ack()
		}
		c.logger.Info().Int("count", len(events)).Msg("wrote audit events (legacy)")
	}
}
