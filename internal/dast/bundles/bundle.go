// Package bundles provides the Bundle struct representing a DAST auth bundle,
// along with canonical JSON serialization for HMAC computation and integrity
// verification.
package bundles

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Cookie represents an HTTP cookie captured during a DAST auth session.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Expires  string `json:"expires,omitempty"`
	HttpOnly bool   `json:"http_only,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

// SessionCapture holds the raw cookies and headers captured from an
// authenticated browser session.
type SessionCapture struct {
	Cookies []Cookie          `json:"cookies"`
	Headers map[string]string `json:"headers"`
}

// canonicalHeader is used to serialize a headers map as a sorted slice of
// key/value pairs so that JSON encoding is deterministic.
type canonicalHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// canonicalSessionCapture mirrors SessionCapture but replaces the Headers map
// with a sorted slice for deterministic JSON output.
type canonicalSessionCapture struct {
	Cookies []Cookie          `json:"cookies"`
	Headers []canonicalHeader `json:"headers"`
}

// Bundle represents a DAST authentication bundle stored in the platform.
type Bundle struct {
	ID              string `json:"id"`
	SchemaVersion   int    `json:"schema_version"`
	CustomerID      string `json:"customer_id"`
	ProjectID       string `json:"project_id"`
	TargetHost      string `json:"target_host"`
	TargetPrincipal string `json:"target_principal,omitempty"`
	Type            string `json:"type"`

	CapturedSession SessionCapture `json:"captured_session"`

	CreatedByUserID string    `json:"created_by_user_id"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`

	CaptchaInFlow       bool `json:"captcha_in_flow,omitempty"`
	AutomatableRefresh  bool `json:"automatable_refresh,omitempty"`
	TTLSeconds          int  `json:"ttl_seconds"`
}

// canonicalBundle mirrors Bundle but uses canonicalSessionCapture so the
// headers map is serialized in sorted order for HMAC determinism.
type canonicalBundle struct {
	ID              string                  `json:"id"`
	SchemaVersion   int                     `json:"schema_version"`
	CustomerID      string                  `json:"customer_id"`
	ProjectID       string                  `json:"project_id"`
	TargetHost      string                  `json:"target_host"`
	TargetPrincipal string                  `json:"target_principal,omitempty"`
	Type            string                  `json:"type"`
	CapturedSession canonicalSessionCapture `json:"captured_session"`
	CreatedByUserID string                  `json:"created_by_user_id"`
	CreatedAt       string                  `json:"created_at"`
	ExpiresAt       string                  `json:"expires_at"`
	CaptchaInFlow   bool                    `json:"captcha_in_flow,omitempty"`
	AutomatableRefresh bool                 `json:"automatable_refresh,omitempty"`
	TTLSeconds      int                     `json:"ttl_seconds"`
}

// CanonicalJSON returns a deterministic JSON encoding of b suitable for HMAC
// computation. The Headers map is serialized as a sorted slice of {key, value}
// objects to avoid Go map iteration non-determinism. Times are serialized as
// RFC3339Nano UTC. HTML escaping is disabled so that '&', '<', '>' are not
// rewritten.
func (b *Bundle) CanonicalJSON() ([]byte, error) {
	// Build sorted headers slice.
	hdrs := make([]canonicalHeader, 0, len(b.CapturedSession.Headers))
	for k, v := range b.CapturedSession.Headers {
		hdrs = append(hdrs, canonicalHeader{Key: k, Value: v})
	}
	sort.Slice(hdrs, func(i, j int) bool {
		return hdrs[i].Key < hdrs[j].Key
	})

	cb := canonicalBundle{
		ID:            b.ID,
		SchemaVersion: b.SchemaVersion,
		CustomerID:    b.CustomerID,
		ProjectID:     b.ProjectID,
		TargetHost:    b.TargetHost,
		TargetPrincipal: b.TargetPrincipal,
		Type:          b.Type,
		CapturedSession: canonicalSessionCapture{
			Cookies: b.CapturedSession.Cookies,
			Headers: hdrs,
		},
		CreatedByUserID:    b.CreatedByUserID,
		CreatedAt:          b.CreatedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:          b.ExpiresAt.UTC().Format(time.RFC3339Nano),
		CaptchaInFlow:      b.CaptchaInFlow,
		AutomatableRefresh: b.AutomatableRefresh,
		TTLSeconds:         b.TTLSeconds,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cb); err != nil {
		return nil, fmt.Errorf("bundles: canonical JSON encode: %w", err)
	}
	// json.Encoder always appends a trailing newline; strip it.
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// ComputeIntegrityHMAC computes an HMAC-SHA-256 over the canonical JSON of b
// using the provided key.
func (b *Bundle) ComputeIntegrityHMAC(key []byte) ([]byte, error) {
	canonical, err := b.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("bundles: compute HMAC: %w", err)
	}
	h := hmac.New(sha256.New, key)
	h.Write(canonical)
	return h.Sum(nil), nil
}

// VerifyIntegrityHMAC verifies that mac is a valid HMAC-SHA-256 over the
// canonical JSON of b under key. The comparison is constant-time.
func (b *Bundle) VerifyIntegrityHMAC(key, mac []byte) (bool, error) {
	canonical, err := b.CanonicalJSON()
	if err != nil {
		return false, fmt.Errorf("bundles: verify HMAC: %w", err)
	}
	h := hmac.New(sha256.New, key)
	h.Write(canonical)
	expected := h.Sum(nil)
	return hmac.Equal(expected, mac), nil
}
