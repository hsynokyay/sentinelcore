// Package query parses audit-log query/export filters into a SQL predicate.
//
// The same parser powers the paginated read endpoint (GET /api/v1/audit)
// AND the export path (POST /api/v1/audit/exports). It refuses to
// compose filters into free-form SQL — every constraint is a parametrised
// placeholder so there is no injection surface.
//
// Caller contract: Build() returns (whereClause, args) where whereClause
// starts with WHERE (or is empty for "no filters"). The caller is
// responsible for adding an ORDER BY / LIMIT to the final statement.
//
// Tenant scope is applied by the caller, NOT by this package. Keeping
// org_id out of the parser prevents the misuse where a platform_admin
// drops it and silently runs cross-tenant.
package query

import (
	"fmt"
	"strings"
	"time"
)

// Filter describes the input side of GET /api/v1/audit and POST /exports.
type Filter struct {
	From         *time.Time
	To           *time.Time
	Actions      []string // exact matches OR glob ("risk.*")
	ActorID      string
	ResourceType string
	ResourceID   string
	Result       string // success | failure | denied

	// Keyset pagination cursor (opaque to the caller; Build embeds the
	// predicate directly). Empty = first page.
	AfterTimestamp *time.Time
	AfterID        *int64
}

// BuildResult is a parametrised WHERE predicate + its args.
// ArgOffset is the number of placeholders consumed so the caller can
// append $N+1, $N+2 for their tenant / limit binds.
type BuildResult struct {
	Where     string
	Args      []any
	ArgOffset int
}

// Build returns a parametrised WHERE clause.
func (f Filter) Build() BuildResult {
	var conditions []string
	var args []any

	add := func(cond string, arg any) {
		args = append(args, arg)
		conditions = append(conditions, fmt.Sprintf(cond, len(args)))
	}

	if f.From != nil {
		add("timestamp >= $%d", *f.From)
	}
	if f.To != nil {
		add("timestamp < $%d", *f.To)
	}
	if len(f.Actions) > 0 {
		// Separate literal matches from glob matches.
		var literals []string
		var globs []string
		for _, a := range f.Actions {
			if strings.HasSuffix(a, ".*") {
				globs = append(globs, strings.TrimSuffix(a, "*")+"%")
			} else {
				literals = append(literals, a)
			}
		}
		var parts []string
		if len(literals) > 0 {
			args = append(args, literals)
			parts = append(parts, fmt.Sprintf("action = ANY($%d)", len(args)))
		}
		for _, g := range globs {
			args = append(args, g)
			parts = append(parts, fmt.Sprintf("action LIKE $%d", len(args)))
		}
		if len(parts) > 0 {
			conditions = append(conditions,
				"("+strings.Join(parts, " OR ")+")")
		}
	}
	if f.ActorID != "" {
		add("actor_id = $%d", f.ActorID)
	}
	if f.ResourceType != "" {
		add("resource_type = $%d", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("resource_id = $%d", f.ResourceID)
	}
	if f.Result != "" {
		add("result = $%d", f.Result)
	}

	// Keyset pagination over (timestamp, id) DESC. Bind the timestamp
	// twice to avoid relying on pgx's placeholder-reuse semantics —
	// cheap and explicit.
	if f.AfterTimestamp != nil && f.AfterID != nil {
		args = append(args, *f.AfterTimestamp)
		tsPos1 := len(args)
		args = append(args, *f.AfterTimestamp)
		tsPos2 := len(args)
		args = append(args, *f.AfterID)
		idPos := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(timestamp < $%d OR (timestamp = $%d AND id < $%d))",
			tsPos1, tsPos2, idPos))
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}
	return BuildResult{Where: where, Args: args, ArgOffset: len(args)}
}

// Validate performs sanity checks independent of SQL: range sanity,
// allowed enum values.
func (f Filter) Validate() error {
	if f.From != nil && f.To != nil && f.To.Before(*f.From) {
		return fmt.Errorf("audit query: to < from")
	}
	if f.Result != "" {
		switch f.Result {
		case "success", "failure", "denied":
		default:
			return fmt.Errorf("audit query: result must be success|failure|denied")
		}
	}
	for _, a := range f.Actions {
		// Glob is only supported as a trailing ".*".
		if strings.Contains(a, "*") && !strings.HasSuffix(a, ".*") {
			return fmt.Errorf("audit query: glob only supported as trailing .*")
		}
	}
	return nil
}
