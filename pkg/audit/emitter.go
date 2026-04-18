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
//
// Before publishing the event is passed through the redactor, which:
//   - drops map keys matching the secret deny-list,
//   - truncates string values longer than 512 chars,
//   - records dropped paths in details._redacted so downstream consumers
//     see WHICH keys were scrubbed without seeing the values.
//
// Auto-generates EventID and Timestamp if not set.
func (e *Emitter) Emit(ctx context.Context, event AuditEvent) error {
	if event.EventID == "" {
		event.EventID = uuid.New().String()
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	// Redact Details in-place so handlers can't accidentally leak a secret
	// value they placed inline. Redact() returns a fresh map, never
	// mutating the caller's.
	if m, ok := event.Details.(map[string]any); ok && len(m) > 0 {
		cleaned, dropped := Redact(m)
		if len(dropped) > 0 {
			cleaned["_redacted"] = dropped
		}
		event.Details = cleaned
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
