package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
)

// Emitter publishes audit events to NATS JetStream.
type Emitter struct {
	js jetstream.JetStream
}

// NewEmitter creates a new audit event emitter.
func NewEmitter(js jetstream.JetStream) *Emitter {
	return &Emitter{js: js}
}

// Emit publishes an audit event to the audit.events subject.
// It auto-generates EventID and Timestamp if not set.
func (e *Emitter) Emit(ctx context.Context, event AuditEvent) error {
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("audit.Emit: marshal: %w", err)
	}

	_, err = e.js.Publish(ctx, "audit.events", data)
	if err != nil {
		return fmt.Errorf("audit.Emit: publish: %w", err)
	}
	return nil
}
