// Package compliance is the SentinelCore compliance catalog and mapping
// layer. It exposes a small, deterministic resolver that converts a
// CWE/OWASP/internal identifier into the set of compliance controls that
// apply for a given organization, blending normative built-in mappings
// shipped via seed migration 025 with tenant-authored overrides stored
// under their org_id.
//
// The shapes here intentionally stay value-flat: handlers, exporters,
// and worker code only need ControlRef, while CRUD endpoints reach for
// Catalog/Item directly.
package compliance

import "github.com/google/uuid"

// Catalog is a normative or tenant-owned compliance framework
// (e.g. OWASP Top 10 2021, PCI DSS 4.0, NIST 800-53 R5, or an internal
// "INTERNAL_SEC" custom catalog).
//
// OrgID is nil for the built-in catalogs that ship with SentinelCore;
// tenant catalogs always have OrgID set.
type Catalog struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       *uuid.UUID `json:"org_id,omitempty"`
	Code        string     `json:"code"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description,omitempty"`
	IsBuiltin   bool       `json:"is_builtin"`
}

// Item is a single control inside a Catalog (e.g. OWASP "A03",
// PCI "6.2.4", or an internal "SEC-007").
type Item struct {
	ID          uuid.UUID `json:"id"`
	CatalogID   uuid.UUID `json:"catalog_id"`
	ControlID   string    `json:"control_id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
}

// Mapping links a finding-side identifier (CWE, OWASP, internal) to a
// concrete control item. Built-in mappings have OrgID nil; tenant
// overrides have OrgID set.
type Mapping struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           *uuid.UUID `json:"org_id,omitempty"`
	SourceKind      string     `json:"source_kind"`
	SourceCode      string     `json:"source_code"`
	TargetControlID uuid.UUID  `json:"target_control_id"`
	Confidence      string     `json:"confidence"`
	SourceVersion   string     `json:"source_version,omitempty"`
}

// ControlRef is the resolver output for a single (cwe, org) lookup. It
// joins catalog + item + mapping fields into one row so callers (SARIF
// emitter, Markdown report, finding-detail UI) only need a single trip.
type ControlRef struct {
	CatalogCode string `json:"catalog_code"`
	CatalogName string `json:"catalog_name"`
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Confidence  string `json:"confidence"`
	SourceKind  string `json:"source_kind"`
	SourceCode  string `json:"source_code"`
}
