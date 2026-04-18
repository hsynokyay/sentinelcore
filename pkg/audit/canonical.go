package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// Canonical produces a deterministic byte representation of an AuditEvent +
// previous_hash, suitable for HMAC input. It is an RFC 8785-lite scheme:
//
//   - Keys at every level are sorted lexicographically.
//   - No whitespace between tokens.
//   - Numbers emitted by Go's encoding/json (float64 base) — acceptable
//     because we never round-trip HMAC'd events back through the same
//     encoder in a different runtime.
//   - Nil / missing fields are omitted (no "key":null).
//   - previous_hash is appended OUTSIDE the JSON object with a '|' delimiter
//     so the chain marker can never collide with a field value.
//
// The output is a string for ease of hashing; callers take []byte(s) for HMAC.
func Canonical(e AuditEvent, previousHash string) string {
	// Walk the event into a flat, ordered map. Omit zero-value strings
	// (including the pre-hash fields the consumer writes later).
	fields := map[string]any{}
	if e.EventID != "" {
		fields["event_id"] = e.EventID
	}
	if e.Timestamp != "" {
		fields["timestamp"] = e.Timestamp
	}
	if e.ActorType != "" {
		fields["actor_type"] = e.ActorType
	}
	if e.ActorID != "" {
		fields["actor_id"] = e.ActorID
	}
	if e.ActorIP != "" {
		fields["actor_ip"] = e.ActorIP
	}
	if e.Action != "" {
		fields["action"] = e.Action
	}
	if e.ResourceType != "" {
		fields["resource_type"] = e.ResourceType
	}
	if e.ResourceID != "" {
		fields["resource_id"] = e.ResourceID
	}
	if e.OrgID != "" {
		fields["org_id"] = e.OrgID
	}
	if e.TeamID != "" {
		fields["team_id"] = e.TeamID
	}
	if e.ProjectID != "" {
		fields["project_id"] = e.ProjectID
	}
	if e.Result != "" {
		fields["result"] = e.Result
	}
	if e.Details != nil {
		// Convert any typed map/struct to a generic map for consistent key walk.
		if m, ok := toMap(e.Details); ok && len(m) > 0 {
			fields["details"] = m
		}
	}

	var buf bytes.Buffer
	writeValue(&buf, fields)
	buf.WriteByte('|')
	buf.WriteString(previousHash)
	return buf.String()
}

// toMap coerces Details (which is `any`) into a map[string]any so the canonical
// walker can sort its keys. Returns (nil, false) for non-map shapes.
//
// ALWAYS goes through JSON marshal+unmarshal so that nested typed slices
// (e.g. []string, []int) become []any — exactly the form the verifier will
// see after reading the JSONB column back. Without this round-trip the
// writer's canonical output and the verifier's diverge on event payloads
// that contain typed slices (the redactor's _redacted field is the common
// case), producing false HMAC-mismatch alerts.
func toMap(v any) (map[string]any, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false
	}
	return m, true
}

// writeValue renders a value into buf in canonical form: sorted maps,
// non-whitespace JSON, no trailing comma.
func writeValue(buf *bytes.Buffer, v any) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			writeValue(buf, t[k])
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeValue(buf, x)
		}
		buf.WriteByte(']')
	case string:
		writeString(buf, t)
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		buf.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
	case int:
		buf.WriteString(strconv.FormatInt(int64(t), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case nil:
		buf.WriteString("null")
	default:
		// Fallback: let encoding/json handle exotic types. This breaks strict
		// determinism for nested maps inside typed structs but is only reached
		// by deliberate callers.
		b, _ := json.Marshal(t)
		buf.Write(b)
	}
	_ = fmt.Sprintf // keep import usable for future structured errors
}

// writeString emits a JSON-escaped string with minimal whitespace.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if c < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, c)
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}
