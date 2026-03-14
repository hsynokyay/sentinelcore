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
	case "version":
		cli.PrintVersion()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: sentinelcore-cli <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  bootstrap  Initialize the system with default org, team, and admin user")
	fmt.Println("  version    Show version information")
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
