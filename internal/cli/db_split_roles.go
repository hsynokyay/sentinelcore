package cli

// db_split_roles.go — `sentinelcore-cli db-split-roles` commands.
//
// After migration 037 creates the four split roles with NULL passwords,
// this CLI either:
//
//   --generate   Generate fresh 32-byte passwords, print them to
//                stdout in KEY=value env format. Operator redirects
//                to a file (which should then move to Vault).
//
//   --apply      Read role passwords from SC_SPLIT_ROLE_*_PASSWORD
//                env vars and run ALTER ROLE ... PASSWORD for each.
//                Passwords in env ARE the Vault → env handoff path.
//
// The two-phase design keeps the plaintext password out of the
// binary + audit log: --generate only prints, --apply only reads.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

var splitRoles = []string{
	"sentinelcore_controlplane",
	"sentinelcore_audit_writer",
	"sentinelcore_worker",
	"sentinelcore_readonly",
}

// RunDBSplitRolesCommand dispatches sentinelcore-cli db-split-roles
// subcommands.
func RunDBSplitRolesCommand(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) == 0 {
		return errors.New(`usage: sentinelcore-cli db-split-roles <subcommand>

Subcommands:
  --generate   Print fresh KEY=value env lines for each role
               (writes to stdout only; never touches the DB).
  --apply      Read SC_SPLIT_ROLE_<ROLE>_PASSWORD env vars and run
               ALTER ROLE ... PASSWORD for each.
  --verify     Connect as each role and print SELECT current_user +
               the schemas it has USAGE on. No writes.

Example rollout:

    sentinelcore-cli db-split-roles --generate > /tmp/roles.env
    # move /tmp/roles.env → Vault, or into /opt/sentinelcore/env/roles.env
    export $(cat /opt/sentinelcore/env/roles.env | xargs)
    sentinelcore-cli db-split-roles --apply
    sentinelcore-cli db-split-roles --verify`)
	}

	switch args[0] {
	case "--generate":
		return dbSplitGenerate()
	case "--apply":
		return dbSplitApply(ctx, pool)
	case "--verify":
		return dbSplitVerify(ctx, pool)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// dbSplitGenerate prints 32-byte URL-safe random passwords for each
// role as KEY=value lines suitable for /opt/sentinelcore/env/roles.env.
// Never writes to the DB.
func dbSplitGenerate() error {
	for _, role := range splitRoles {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return fmt.Errorf("rand: %w", err)
		}
		pw := base64.RawURLEncoding.EncodeToString(raw)
		envKey := roleEnvKey(role)
		fmt.Printf("%s=%s\n", envKey, pw)
	}
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "NEXT:")
	fmt.Fprintln(os.Stderr, "  1. Redirect above to /opt/sentinelcore/env/roles.env (chmod 0600, chown sentinelcore).")
	fmt.Fprintln(os.Stderr, "  2. Source it before running --apply:")
	fmt.Fprintln(os.Stderr, "       export $(cat /opt/sentinelcore/env/roles.env | xargs)")
	fmt.Fprintln(os.Stderr, "       sentinelcore-cli db-split-roles --apply")
	fmt.Fprintln(os.Stderr, "  3. Update each service's DATABASE_URL to its dedicated role + new password.")
	return nil
}

// dbSplitApply reads the passwords from env and runs ALTER ROLE
// against each split role. Runs as the current DB user (sentinelcore
// monolithic role) which is the migration owner and can ALTER other
// roles it created via CREATE ROLE.
func dbSplitApply(ctx context.Context, pool *pgxpool.Pool) error {
	for _, role := range splitRoles {
		pw := os.Getenv(roleEnvKey(role))
		if pw == "" {
			return fmt.Errorf("missing env %s — run --generate and source the output first",
				roleEnvKey(role))
		}
		// ALTER ROLE does NOT accept a parameter for the password
		// literal, so we must build the statement inline. The
		// password is guaranteed URL-safe base64 so there's no
		// escaping concern, but quote anyway as defence in depth.
		quoted := "'" + strings.ReplaceAll(pw, "'", "''") + "'"
		sql := fmt.Sprintf("ALTER ROLE %s PASSWORD %s", role, quoted)
		if _, err := pool.Exec(ctx, sql); err != nil {
			return fmt.Errorf("alter role %s: %w", role, err)
		}
		fmt.Printf("  ✓ password set for %s\n", role)
	}
	return nil
}

// dbSplitVerify opens a fresh connection AS each role and runs a
// minimal grant probe. Prints the schemas each role can USE. Catches
// accidental grant drift between the migration and reality.
func dbSplitVerify(ctx context.Context, pool *pgxpool.Pool) error {
	// We need the server's host/port + DB name to build per-role
	// DSNs. Parse them off the pool's config.
	cfg := pool.Config().ConnConfig
	for _, role := range splitRoles {
		pw := os.Getenv(roleEnvKey(role))
		if pw == "" {
			fmt.Printf("  ? skip %s — env %s unset, cannot dial as this role\n",
				role, roleEnvKey(role))
			continue
		}
		dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			role, pw, cfg.Host, cfg.Port, cfg.Database)
		p2, err := pgxpool.New(ctx, dsn)
		if err != nil {
			fmt.Printf("  ✗ %s — dial: %v\n", role, err)
			continue
		}
		var who string
		var schemas []string
		if err := p2.QueryRow(ctx, `SELECT current_user`).Scan(&who); err != nil {
			p2.Close()
			fmt.Printf("  ✗ %s — current_user: %v\n", role, err)
			continue
		}
		rows, err := p2.Query(ctx, `
			SELECT nspname FROM pg_namespace
			WHERE has_schema_privilege(current_user, nspname, 'USAGE')
			  AND nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'
			ORDER BY nspname`)
		if err == nil {
			for rows.Next() {
				var s string
				if rows.Scan(&s) == nil {
					schemas = append(schemas, s)
				}
			}
			rows.Close()
		}
		p2.Close()
		fmt.Printf("  ✓ %s (current_user=%s) — USAGE: [%s]\n",
			role, who, strings.Join(schemas, ", "))
	}
	return nil
}

// roleEnvKey maps a role to its env variable.
// sentinelcore_controlplane → SC_SPLIT_ROLE_CONTROLPLANE_PASSWORD
func roleEnvKey(role string) string {
	short := strings.TrimPrefix(role, "sentinelcore_")
	return "SC_SPLIT_ROLE_" + strings.ToUpper(short) + "_PASSWORD"
}
