package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/sentinelcore/sentinelcore/internal/compliance"
	"github.com/sentinelcore/sentinelcore/internal/policy"
)

// ListComplianceCatalogs returns every catalog visible to the caller's
// org (built-ins + tenant-owned).
//
// GET /api/v1/compliance/catalogs
func (h *Handlers) ListComplianceCatalogs(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.catalogs.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	cats, err := compliance.ListCatalogs(r.Context(), h.pool, orgID)
	if err != nil {
		h.logger.Error().Err(err).Msg("list catalogs")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"catalogs": cats})
}

// ListComplianceCatalogItems returns every item under a catalog.
//
// GET /api/v1/compliance/catalogs/{catalog_id}/items
func (h *Handlers) ListComplianceCatalogItems(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.catalogs.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	catalogID, err := uuid.Parse(r.PathValue("catalog_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "catalog_id must be a uuid", "BAD_REQUEST")
		return
	}
	items, err := compliance.ListItems(r.Context(), h.pool, orgID, catalogID)
	if err != nil {
		h.logger.Error().Err(err).Msg("list catalog items")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// ListComplianceMappings returns the merged built-in + tenant mapping
// set with optional filters.
//
// GET /api/v1/compliance/mappings?source_kind=cwe&source_code=CWE-79
func (h *Handlers) ListComplianceMappings(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.mappings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	sourceKind := r.URL.Query().Get("source_kind")
	sourceCode := r.URL.Query().Get("source_code")
	mps, err := compliance.ListMappings(r.Context(), h.pool, orgID, sourceKind, sourceCode)
	if err != nil {
		h.logger.Error().Err(err).Msg("list mappings")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mappings": mps})
}

// ResolveComplianceControls is the resolver-shaped endpoint the UI / SARIF
// emitter call to map a single CWE to a list of ControlRefs.
//
// GET /api/v1/compliance/resolve?cwe=79
func (h *Handlers) ResolveComplianceControls(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.mappings.read") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	cweStr := r.URL.Query().Get("cwe")
	if cweStr == "" {
		writeError(w, http.StatusBadRequest, "cwe query param required", "BAD_REQUEST")
		return
	}
	cweID, perr := strconv.Atoi(cweStr)
	if perr != nil || cweID <= 0 {
		writeError(w, http.StatusBadRequest, "cwe must be a positive integer", "BAD_REQUEST")
		return
	}
	refs, err := compliance.ResolveControls(r.Context(), h.pool, orgID, cweID)
	if err != nil {
		h.logger.Error().Err(err).Msg("resolve controls")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"controls": refs, "cwe_id": cweID})
}

// CreateComplianceCatalog creates a tenant-owned catalog.
//
// POST /api/v1/compliance/catalogs
// Body: { code, name, version, description? }
func (h *Handlers) CreateComplianceCatalog(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.catalogs.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	var body struct {
		Code        string `json:"code"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	cat, err := compliance.CreateCatalog(r.Context(), h.pool, orgID, body.Code, body.Name, body.Version, body.Description)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}
	h.emitAuditEvent(r.Context(), "compliance.catalog.created", "user", user.UserID, "catalog", cat.ID.String(), r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, cat)
}

// CreateComplianceItem creates a tenant-owned control item under a
// tenant-owned catalog. Built-in catalogs reject with 403.
//
// POST /api/v1/compliance/catalogs/{catalog_id}/items
// Body: { control_id, title, description? }
func (h *Handlers) CreateComplianceItem(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.catalogs.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	catalogID, err := uuid.Parse(r.PathValue("catalog_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "catalog_id must be a uuid", "BAD_REQUEST")
		return
	}
	var body struct {
		ControlID   string `json:"control_id"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	it, err := compliance.CreateItem(r.Context(), h.pool, orgID, catalogID, body.ControlID, body.Title, body.Description)
	if err != nil {
		if errors.Is(err, compliance.ErrBuiltinReadOnly) {
			writeError(w, http.StatusForbidden, "cannot modify built-in catalog", "FORBIDDEN")
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "catalog not found", "NOT_FOUND")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}
	h.emitAuditEvent(r.Context(), "compliance.item.created", "user", user.UserID, "item", it.ID.String(), r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, it)
}

// CreateComplianceMapping creates a tenant-owned mapping (always
// confidence='custom'). The target item must be visible to the caller
// (built-in or owned by the same org).
//
// POST /api/v1/compliance/mappings
// Body: { source_kind, source_code, target_control_id, source_version? }
func (h *Handlers) CreateComplianceMapping(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.mappings.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	var body struct {
		SourceKind      string    `json:"source_kind"`
		SourceCode      string    `json:"source_code"`
		TargetControlID uuid.UUID `json:"target_control_id"`
		SourceVersion   string    `json:"source_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", "BAD_REQUEST")
		return
	}
	if body.TargetControlID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "target_control_id is required", "BAD_REQUEST")
		return
	}
	m, err := compliance.CreateMapping(r.Context(), h.pool, orgID,
		body.SourceKind, body.SourceCode, body.TargetControlID, body.SourceVersion)
	if err != nil {
		if errors.Is(err, compliance.ErrBuiltinReadOnly) {
			writeError(w, http.StatusForbidden, "cannot map to a control owned by another org", "FORBIDDEN")
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "target control item not found", "NOT_FOUND")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error(), "BAD_REQUEST")
		return
	}
	h.emitAuditEvent(r.Context(), "compliance.mapping.created", "user", user.UserID, "mapping", m.ID.String(), r.RemoteAddr, "success")
	writeJSON(w, http.StatusCreated, m)
}

// DeleteComplianceMapping removes a tenant-owned mapping. Built-in
// mappings reject with 403.
//
// DELETE /api/v1/compliance/mappings/{id}
func (h *Handlers) DeleteComplianceMapping(w http.ResponseWriter, r *http.Request) {
	user := requireAuth(w, r)
	if user == nil {
		return
	}
	if !policy.Evaluate(user.Role, "compliance.mappings.write") {
		writeError(w, http.StatusForbidden, "insufficient permissions", "FORBIDDEN")
		return
	}
	orgID, err := uuid.Parse(user.OrgID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid org id on session", "BAD_REQUEST")
		return
	}
	mappingID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "id must be a uuid", "BAD_REQUEST")
		return
	}
	err = compliance.DeleteMapping(r.Context(), h.pool, orgID, mappingID)
	if err != nil {
		if errors.Is(err, compliance.ErrBuiltinReadOnly) {
			writeError(w, http.StatusForbidden, "cannot delete built-in mapping", "FORBIDDEN")
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "mapping not found", "NOT_FOUND")
			return
		}
		h.logger.Error().Err(err).Msg("delete mapping")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	h.emitAuditEvent(r.Context(), "compliance.mapping.deleted", "user", user.UserID, "mapping", mappingID.String(), r.RemoteAddr, "success")
	w.WriteHeader(http.StatusNoContent)
}
