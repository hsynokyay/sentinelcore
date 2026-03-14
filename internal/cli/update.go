package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

const defaultUpdaterURL = "http://localhost:9009"

// RunUpdateCommand dispatches sentinelcore-cli update subcommands.
func RunUpdateCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: sentinelcore-cli update <subcommand>\n  subcommands: verify-bundle, trust-status, lockdown")
	}

	baseURL := os.Getenv("UPDATER_URL")
	if baseURL == "" {
		baseURL = defaultUpdaterURL
	}

	switch args[0] {
	case "verify-bundle":
		return runVerifyBundle(baseURL, args[1:])
	case "trust-status":
		return runTrustStatus(baseURL)
	case "lockdown":
		return runLockdown(baseURL, args[1:])
	default:
		return fmt.Errorf("unknown subcommand: %s", args[0])
	}
}

func runVerifyBundle(baseURL string, args []string) error {
	fs := flag.NewFlagSet("verify-bundle", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "Path to bundle tar.gz")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return fmt.Errorf("--bundle flag is required")
	}

	body, _ := json.Marshal(map[string]string{"bundle_path": *bundlePath})
	resp, err := http.Post(baseURL+"/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(data, &result)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)
	return nil
}

func runTrustStatus(baseURL string) error {
	resp, err := http.Get(baseURL + "/trust-status")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var state map[string]string
	json.Unmarshal(data, &state)

	fmt.Println("Trust State:")
	for k, v := range state {
		fmt.Printf("  %-35s %s\n", k, v)
	}
	return nil
}

func runLockdown(baseURL string, args []string) error {
	fs := flag.NewFlagSet("lockdown", flag.ExitOnError)
	enable := fs.Bool("enable", false, "Enable lockdown mode")
	disable := fs.Bool("disable", false, "Disable lockdown mode")
	reason := fs.String("reason", "manual lockdown", "Reason for enabling lockdown")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*enable && !*disable {
		return fmt.Errorf("specify --enable or --disable")
	}
	if *enable && *disable {
		return fmt.Errorf("cannot specify both --enable and --disable")
	}

	var endpoint string
	var body []byte
	if *enable {
		endpoint = "/lockdown/enable"
		body, _ = json.Marshal(map[string]string{"reason": *reason})
	} else {
		endpoint = "/lockdown/disable"
		body = []byte("{}")
	}

	resp, err := http.Post(baseURL+endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	fmt.Println(string(data))
	return nil
}
