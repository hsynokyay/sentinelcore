package main

import (
	"fmt"
	"os"
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
	default:
		printDastUsage()
		return fmt.Errorf("dast: unknown subcommand %q", args[0])
	}
}

func printDastUsage() {
	fmt.Fprintln(os.Stderr, "Usage: sentinelcore-cli dast <subcommand> [options]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  record    Record an authenticated session for DAST scanning")
}
