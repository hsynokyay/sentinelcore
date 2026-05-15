package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
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
	// Normalise ActorIP: callers often pass r.RemoteAddr ("ip:port") which
	// cannot be stored in the INET column and would otherwise diverge
	// between writer canonical (has value) and verifier canonical (empty
	// after INET NULL round-trip), breaking the HMAC chain.
	event.ActorIP = normaliseIP(event.ActorIP)

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

// normaliseIP strips a trailing port (":58242"), validates the remainder
// via netip.ParseAddr, and returns the canonical string representation.
// Empty input, unparseable input, or an attached port that cannot be
// split returns "" — the writer then stores NULL in the INET column and
// both writer and verifier produce identical canonical forms.
func normaliseIP(raw string) string {
	if raw == "" {
		return ""
	}
	// IPv6 with port: "[::1]:1234". IPv4 with port: "10.0.0.1:1234".
	// Bare addresses: "10.0.0.1", "::1", "fe80::1%en0".
	candidates := []string{raw}
	if i := strings.LastIndex(raw, ":"); i > 0 && !strings.Contains(raw[i+1:], ":") {
		// Trailing :port style; strip + try.
		stripped := raw[:i]
		stripped = strings.TrimPrefix(strings.TrimSuffix(stripped, "]"), "[")
		candidates = append(candidates, stripped)
	}
	for _, c := range candidates {
		if addr, err := netip.ParseAddr(c); err == nil {
			return addr.String()
		}
	}
	return ""
}
