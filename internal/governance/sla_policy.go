package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FallbackSLADays is the hard-coded fallback used when neither a project
// override nor an org-level default exists. The keys (critical/high/medium/low)
// are required by the project_sla_policies CHECK constraint.
var FallbackSLADays = map[string]int{
	"critical": 3,
	"high":     7,
	"medium":   30,
	"low":      90,
}

// ResolveSLADays returns the effective SLA-days map for a (org, project) pair.
// Precedence (highest first):
//
//  1. governance.project_sla_policies.sla_days for projectID
//  2. governance.org_settings.default_finding_sla_days for orgID
//  3. FallbackSLADays
//
// The function intentionally uses the service-role pool — it is meant to be
// called from workers that iterate across orgs, and from API handlers that
// have already authenticated the caller and do not need RLS scoping.
func ResolveSLADays(ctx context.Context, pool *pgxpool.Pool, orgID, projectID uuid.UUID) (map[string]int, error) {
	if pool == nil {
		return nil, errors.New("governance: pool is nil")
	}

	// 1. Project override.
	var raw []byte
	err := pool.QueryRow(ctx, `
		SELECT sla_days FROM governance.project_sla_policies WHERE project_id = $1
	`, projectID).Scan(&raw)
	if err == nil {
		out, decodeErr := decodeSLADays(raw)
		if decodeErr == nil {
			return out, nil
		}
		// Fall through on decode error — log via return to avoid hiding bugs.
		return nil, fmt.Errorf("governance: decode project sla_days: %w", decodeErr)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("governance: query project sla policy: %w", err)
	}

	// 2. Org default.
	err = pool.QueryRow(ctx, `
		SELECT default_finding_sla_days FROM governance.org_settings WHERE org_id = $1
	`, orgID).Scan(&raw)
	if err == nil {
		out, decodeErr := decodeSLADays(raw)
		if decodeErr == nil {
			return out, nil
		}
		return nil, fmt.Errorf("governance: decode org sla_days: %w", decodeErr)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("governance: query org settings sla: %w", err)
	}

	// 3. Hard-coded defaults.
	return cloneSLADays(FallbackSLADays), nil
}

// decodeSLADays unmarshals a JSONB blob into map[string]int and validates that
// the four required severities are present.
func decodeSLADays(raw []byte) (map[string]int, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty sla_days")
	}
	out := map[string]int{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for _, k := range []string{"critical", "high", "medium", "low"} {
		if _, ok := out[k]; !ok {
			return nil, fmt.Errorf("missing severity %q", k)
		}
	}
	return out, nil
}

// cloneSLADays returns a defensive copy so callers cannot mutate the
// package-level FallbackSLADays map.
func cloneSLADays(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
