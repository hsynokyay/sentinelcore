package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sentinelcore/sentinelcore/internal/cli"
	"github.com/sentinelcore/sentinelcore/pkg/db"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "bootstrap":
		runBootstrap()
	case "update":
		if err := cli.RunUpdateCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "rotate":
		runRotate()
	case "db-split-roles":
		runDBSplitRoles()
	case "version":
		cli.PrintVersion()
	case "dast":
		if err := runDastCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

// runRotate opens a short-lived pool with the bootstrap DB creds and
// delegates to internal/cli.RunRotateCommand. The rotation writer
// needs INSERT on auth.aes_keys / audit.hmac_keys / auth.apikey_peppers,
// which the monolithic sentinelcore role already holds.
func runRotate() {
	cfg := db.Config{
		Host:     envOrDefault("DB_HOST", "localhost"),
		Port:     envIntOrDefault("DB_PORT", 5432),
		Database: envOrDefault("DB_NAME", "sentinelcore"),
		User:     envOrDefault("DB_USER", "sentinelcore"),
		Password: envOrDefault("DB_PASSWORD", "dev-password"),
		MaxConns: 2,
	}
	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rotate: connect to db: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := cli.RunRotateCommand(ctx, pool, os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "rotate: %v\n", err)
		os.Exit(1)
	}
}

// runDBSplitRoles is the same pool setup as runRotate; the operations
// require CREATEROLE / ALTER ROLE privileges which the monolithic
// sentinelcore role holds by default (Postgres grants it to the db
// owner). On the deploy VPS this runs once per environment.
func runDBSplitRoles() {
	cfg := db.Config{
		Host:     envOrDefault("DB_HOST", "localhost"),
		Port:     envIntOrDefault("DB_PORT", 5432),
		Database: envOrDefault("DB_NAME", "sentinelcore"),
		User:     envOrDefault("DB_USER", "sentinelcore"),
		Password: envOrDefault("DB_PASSWORD", "dev-password"),
		MaxConns: 2,
	}
	ctx := context.Background()
	// --generate doesn't need the DB at all; check it before dialing.
	if len(os.Args) >= 3 && os.Args[2] == "--generate" {
		if err := cli.RunDBSplitRolesCommand(ctx, nil, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "db-split-roles: %v\n", err)
			os.Exit(1)
		}
		return
	}
	pool, err := db.NewPool(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db-split-roles: connect to db: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := cli.RunDBSplitRolesCommand(ctx, pool, os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "db-split-roles: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sentinelcore-cli <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  bootstrap  Initialize the system with default org, team, and admin user")
	fmt.Println("  update     Manage secure updates (verify-bundle, trust-status, lockdown)")
	fmt.Println("  rotate     Rotate secrets: aes/<purpose>, hmac/audit, apikey-pepper")
	fmt.Println("  db-split-roles  Generate/apply/verify split-role passwords (Phase 7 Wave 3)")
	fmt.Println("  version    Show version information")
	fmt.Println("  dast       DAST commands (record, ...)")
	fmt.Println()
	fmt.Println("Bootstrap options:")
	fmt.Println("  --admin-email <email>       Admin email address")
	fmt.Println("  --admin-password <password>  Admin password")
}

func runBootstrap() {
	var email, password string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--admin-email":
			if i+1 < len(args) {
				i++
				email = args[i]
			}
		case "--admin-password":
			if i+1 < len(args) {
				i++
				password = args[i]
			}
		}
	}

	if email == "" || password == "" {
		fmt.Fprintln(os.Stderr, "error: --admin-email and --admin-password are required")
		os.Exit(1)
	}

	cfg := cli.BootstrapConfig{
		AdminEmail:    email,
		AdminPassword: password,
		DBConfig: db.Config{
			Host:     envOrDefault("DB_HOST", "localhost"),
			Port:     envIntOrDefault("DB_PORT", 5432),
			Database: envOrDefault("DB_NAME", "sentinelcore"),
			User:     envOrDefault("DB_USER", "sentinelcore"),
			Password: envOrDefault("DB_PASSWORD", "dev-password"),
			MaxConns: 5,
		},
	}

	if err := cli.Bootstrap(context.Background(), cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			return def
		}
	}
	return n
}
