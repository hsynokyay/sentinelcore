package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/cli"
	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// runDastCommand routes "dast <subcommand>" to the right handler.
func runDastCommand(args []string) error {
	if len(args) == 0 {
		printDastUsage()
		return fmt.Errorf("dast: missing subcommand")
	}
	switch args[0] {
	case "record":
		return runDastRecord(args[1:])
	case "credentials":
		return runDastCredentials(args[1:])
	default:
		printDastUsage()
		return fmt.Errorf("dast: unknown subcommand %q", args[0])
	}
}

func printDastUsage() {
	fmt.Fprintln(os.Stderr, "Usage: sentinelcore-cli dast <subcommand> [options]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  record         Record an authenticated session for DAST scanning")
	fmt.Fprintln(os.Stderr, "  credentials    Manage replay credentials (add|list|remove)")
}

// runDastCredentials wires a credentials.PostgresStore from env settings and
// dispatches to the cli.RunCredentialsCommand handler. Connection settings
// match the rest of the CLI (DATABASE_URL or DB_* vars). The KMS master key
// comes from SENTINEL_KMS_MASTER_KEY (32 bytes); without it we fall back to
// the local provider only when running outside production.
func runDastCredentials(args []string) error {
	ctx := context.Background()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = fmt.Sprintf(
			"postgres://%s:%s@%s:%d/%s?sslmode=disable",
			envOrDefault("DB_USER", "sentinelcore"),
			envOrDefault("DB_PASSWORD", "dev-password"),
			envOrDefault("DB_HOST", "localhost"),
			envIntOrDefault("DB_PORT", 5432),
			envOrDefault("DB_NAME", "sentinelcore"),
		)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("dast credentials: connect: %w", err)
	}
	defer pool.Close()

	master := os.Getenv("SENTINEL_KMS_MASTER_KEY")
	if len(master) != 32 {
		return fmt.Errorf("dast credentials: SENTINEL_KMS_MASTER_KEY must be exactly 32 bytes (got %d)", len(master))
	}
	provider := kms.NewLocalProvider([]byte(master))

	store := credentials.NewPostgresStore(pool, provider)
	return cli.RunCredentialsCommand(args, store)
}
