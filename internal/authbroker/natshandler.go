package authbroker

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
)

// SessionRequest is the NATS wire format for requesting a new auth session.
type SessionRequest struct {
	ScanJobID string     `json:"scan_job_id"`
	Config    AuthConfig `json:"config"`
}

// SessionResponse is the NATS reply for session creation.
// Credentials are NOT included in the wire format — workers must retrieve
// the session by ID from the broker to get headers/cookies.
type SessionResponse struct {
	SessionID string    `json:"session_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// NATSHandler provides NATS request/reply handling for the Auth Session Broker.
type NATSHandler struct {
	broker *Broker
	js     jetstream.JetStream
	logger zerolog.Logger
}

// NewNATSHandler creates a NATS handler for the Auth Session Broker.
func NewNATSHandler(broker *Broker, js jetstream.JetStream, logger zerolog.Logger) *NATSHandler {
	return &NATSHandler{
		broker: broker,
		js:     js,
		logger: logger.With().Str("component", "auth-nats-handler").Logger(),
	}
}

// Start begins consuming auth session requests from NATS. Blocks until ctx is cancelled.
func (h *NATSHandler) Start(ctx context.Context) error {
	cons, err := h.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "auth-broker",
		FilterSubject: "scan.auth.request",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	h.logger.Info().Msg("Auth broker waiting for session requests...")

	// Also start periodic cleanup
	go h.cleanupLoop(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}

		for msg := range msgs.Messages() {
			var req SessionRequest
			if err := json.Unmarshal(msg.Data(), &req); err != nil {
				h.logger.Error().Err(err).Msg("invalid auth request")
				msg.Ack()
				continue
			}

			h.logger.Info().
				Str("scan_job_id", req.ScanJobID).
				Str("strategy", req.Config.Strategy).
				Msg("processing auth request")

			resp := h.handleRequest(ctx, req)

			// Publish response
			data, _ := json.Marshal(resp)
			h.js.Publish(ctx, fmt.Sprintf("scan.auth.response.%s", req.ScanJobID), data)
			msg.Ack()
		}
	}
}

func (h *NATSHandler) handleRequest(ctx context.Context, req SessionRequest) SessionResponse {
	session, err := h.broker.CreateSession(ctx, req.ScanJobID, req.Config)
	if err != nil {
		return SessionResponse{Error: err.Error()}
	}

	return SessionResponse{
		SessionID: session.ID,
		ExpiresAt: session.ExpiresAt,
	}
}

func (h *NATSHandler) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count := h.broker.CleanExpired()
			if count > 0 {
				h.logger.Info().Int("cleaned", count).Msg("expired sessions cleaned")
			}
		}
	}
}
