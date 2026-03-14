package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

// BootstrapConfig holds parameters for the bootstrap command.
type BootstrapConfig struct {
	AdminEmail    string
	AdminPassword string
	DBConfig      db.Config
}

// Bootstrap initializes the system with a default org, team, and admin user.
func Bootstrap(ctx context.Context, cfg BootstrapConfig) error {
	pool, err := db.NewPool(ctx, cfg.DBConfig)
	if err != nil {
		return fmt.Errorf("bootstrap: connect to database: %w", err)
	}
	defer pool.Close()

	// Check if already bootstrapped
	var bootstrapped bool
	err = pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM updates.trust_state WHERE key = 'bootstrap_completed' AND value = 'true')`,
	).Scan(&bootstrapped)
	if err == nil && bootstrapped {
		return fmt.Errorf("bootstrap: system already bootstrapped")
	}

	// Create default org
	orgID := uuid.New().String()
	now := time.Now().UTC()
	_, err = pool.Exec(ctx,
		`INSERT INTO core.organizations (id, name, display_name, status, created_at, updated_at)
		 VALUES ($1, 'default', 'Default Organization', 'active', $2, $2)`,
		orgID, now)
	if err != nil {
		return fmt.Errorf("bootstrap: create default org: %w", err)
	}
	fmt.Printf("Created default organization: %s\n", orgID)

	// Create default team
	teamID := uuid.New().String()
	_, err = pool.Exec(ctx,
		`INSERT INTO core.teams (id, org_id, name, display_name, created_at, updated_at)
		 VALUES ($1, $2, 'default-team', 'Default Team', $3, $3)`,
		teamID, orgID, now)
	if err != nil {
		return fmt.Errorf("bootstrap: create default team: %w", err)
	}
	fmt.Printf("Created default team: %s\n", teamID)

	// Create admin user
	passwordHash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("bootstrap: hash password: %w", err)
	}

	adminID := uuid.New().String()
	_, err = pool.Exec(ctx,
		`INSERT INTO core.users (id, org_id, email, full_name, password_hash, role, status, created_at, updated_at)
		 VALUES ($1, $2, $3, 'Platform Admin', $4, 'platform_admin', 'active', $5, $5)`,
		adminID, orgID, cfg.AdminEmail, passwordHash, now)
	if err != nil {
		return fmt.Errorf("bootstrap: create admin user: %w", err)
	}
	fmt.Printf("Created admin user: %s (%s)\n", adminID, cfg.AdminEmail)

	// Add admin to default team as team_admin
	_, err = pool.Exec(ctx,
		`INSERT INTO core.team_memberships (team_id, user_id, role, joined_at)
		 VALUES ($1, $2, 'team_admin', $3)`,
		teamID, adminID, now)
	if err != nil {
		return fmt.Errorf("bootstrap: add admin to team: %w", err)
	}
	fmt.Println("Added admin to default team as team_admin")

	// Mark bootstrap as completed
	_, err = pool.Exec(ctx,
		`INSERT INTO updates.trust_state (key, value, updated_at)
		 VALUES ('bootstrap_completed', 'true', $1)
		 ON CONFLICT (key) DO UPDATE SET value = 'true', updated_at = $1`,
		now)
	if err != nil {
		return fmt.Errorf("bootstrap: mark completed: %w", err)
	}

	fmt.Println("Bootstrap completed successfully!")
	return nil
}

// PrintVersion prints version information.
func PrintVersion() {
	fmt.Println("sentinelcore-cli version dev")
}

// RunBootstrapFromPool performs the bootstrap using an existing pool (for testing).
func RunBootstrapFromPool(ctx context.Context, pool *pgxpool.Pool, email, password string) error {
	// Check if already bootstrapped
	var bootstrapped bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM updates.trust_state WHERE key = 'bootstrap_completed' AND value = 'true')`,
	).Scan(&bootstrapped)
	if err == nil && bootstrapped {
		return fmt.Errorf("bootstrap: system already bootstrapped")
	}

	orgID := uuid.New().String()
	now := time.Now().UTC()

	_, err = pool.Exec(ctx,
		`INSERT INTO core.organizations (id, name, display_name, status, created_at, updated_at)
		 VALUES ($1, 'default', 'Default Organization', 'active', $2, $2)`,
		orgID, now)
	if err != nil {
		return fmt.Errorf("bootstrap: create default org: %w", err)
	}

	teamID := uuid.New().String()
	_, err = pool.Exec(ctx,
		`INSERT INTO core.teams (id, org_id, name, display_name, created_at, updated_at)
		 VALUES ($1, $2, 'default-team', 'Default Team', $3, $3)`,
		teamID, orgID, now)
	if err != nil {
		return fmt.Errorf("bootstrap: create default team: %w", err)
	}

	passwordHash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("bootstrap: hash password: %w", err)
	}

	adminID := uuid.New().String()
	_, err = pool.Exec(ctx,
		`INSERT INTO core.users (id, org_id, email, full_name, password_hash, role, status, created_at, updated_at)
		 VALUES ($1, $2, $3, 'Platform Admin', $4, 'platform_admin', 'active', $5, $5)`,
		adminID, orgID, email, passwordHash, now)
	if err != nil {
		return fmt.Errorf("bootstrap: create admin user: %w", err)
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO core.team_memberships (team_id, user_id, role, joined_at)
		 VALUES ($1, $2, 'team_admin', $3)`,
		teamID, adminID, now)
	if err != nil {
		return fmt.Errorf("bootstrap: add admin to team: %w", err)
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO updates.trust_state (key, value, updated_at)
		 VALUES ('bootstrap_completed', 'true', $1)
		 ON CONFLICT (key) DO UPDATE SET value = 'true', updated_at = $1`,
		now)
	if err != nil {
		return fmt.Errorf("bootstrap: mark completed: %w", err)
	}

	return nil
}
