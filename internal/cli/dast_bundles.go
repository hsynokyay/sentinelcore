// Package cli — DAST bundles subcommand (`sentinelcore-cli dast bundles ...`).
//
// Provides operator workflows that complement the recording UI:
//   - `dast bundles list [--status <status>]` lists bundles with a status
//     filter (default: pending_review). Output is one bundle per line:
//     `<id>\t<status>\t<target_host>`.
//   - `dast bundles re-record <id> [--reason <text>] [--start-recording]`
//     calls POST /api/v1/dast/bundles/{id}/re-record on the controlplane,
//     prints the new draft bundle id, and (optionally) prints the next
//     command the operator should run to begin recording.
//
// Authentication uses SENTINELCORE_TOKEN (matches the existing record
// subcommand). API base URL defaults to the production hostname; override
// with --api or SENTINELCORE_API.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BundlesDeps wires the network primitives the bundles CLI needs. Tests
// inject a fake HTTP client + fixed env values; the production binary
// calls NewBundlesDeps to populate from os.Getenv.
type BundlesDeps struct {
	HTTPClient *http.Client
	APIBase    string
	APIToken   string
	Out        io.Writer
	Err        io.Writer
}

// NewBundlesDeps constructs default deps from environment + os streams.
func NewBundlesDeps() BundlesDeps {
	apiBase := os.Getenv("SENTINELCORE_API")
	if apiBase == "" {
		apiBase = "https://sentinelcore.resiliencetech.com.tr"
	}
	return BundlesDeps{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
		APIBase:    apiBase,
		APIToken:   os.Getenv("SENTINELCORE_TOKEN"),
		Out:        os.Stdout,
		Err:        os.Stderr,
	}
}

// RunBundlesCommand dispatches `sentinelcore-cli dast bundles <subcmd>`.
func RunBundlesCommand(args []string, deps BundlesDeps) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: dast bundles list|re-record [...]")
	}
	switch args[0] {
	case "list":
		return runBundlesList(args[1:], deps)
	case "re-record":
		return runBundlesReRecord(args[1:], deps)
	default:
		return fmt.Errorf("unknown bundles subcommand %q", args[0])
	}
}

// listFlags holds parsed flags for `dast bundles list`.
type listFlags struct {
	Status string
}

// parseListFlags supports `--status <name>` only. Unknown flags are an error.
func parseListFlags(args []string) (listFlags, error) {
	var f listFlags
	f.Status = "pending_review"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--status":
			if i+1 >= len(args) {
				return f, fmt.Errorf("--status requires a value")
			}
			f.Status = args[i+1]
			i++
		default:
			return f, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if f.Status == "" {
		return f, fmt.Errorf("--status cannot be empty")
	}
	return f, nil
}

// reRecordFlags holds parsed flags for `dast bundles re-record`.
type reRecordFlags struct {
	BundleID       string
	Reason         string
	StartRecording bool
}

// parseReRecordFlags requires a positional bundle id and accepts
// --reason/--start-recording. The id is parsed (and validated as a UUID)
// before the flag scan so a positional --start-recording cannot shadow it.
func parseReRecordFlags(args []string) (reRecordFlags, error) {
	var f reRecordFlags
	if len(args) < 1 {
		return f, fmt.Errorf("re-record: bundle id required (positional)")
	}
	f.BundleID = args[0]
	if _, err := uuid.Parse(f.BundleID); err != nil {
		return f, fmt.Errorf("invalid bundle id %q: %w", f.BundleID, err)
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--reason":
			if i+1 >= len(args) {
				return f, fmt.Errorf("--reason requires a value")
			}
			f.Reason = args[i+1]
			i++
		case "--start-recording":
			f.StartRecording = true
		default:
			return f, fmt.Errorf("unknown flag %q", args[i])
		}
	}
	return f, nil
}

// bundleListItem is one row from GET /api/v1/dast/bundles.
type bundleListItem struct {
	ID         string `json:"id"`
	Status     string `json:"status,omitempty"`
	TargetHost string `json:"target_host"`
	Type       string `json:"type"`
}

type bundleListResponse struct {
	Bundles []bundleListItem `json:"bundles"`
}

// runBundlesList queries GET /api/v1/dast/bundles?status=<status> and
// prints one row per bundle.
func runBundlesList(args []string, deps BundlesDeps) error {
	flags, err := parseListFlags(args)
	if err != nil {
		return err
	}
	if deps.APIToken == "" {
		return fmt.Errorf("SENTINELCORE_TOKEN (or --token via env) required")
	}
	u, err := url.Parse(deps.APIBase + "/api/v1/dast/bundles")
	if err != nil {
		return fmt.Errorf("bad API base: %w", err)
	}
	q := u.Query()
	q.Set("status", flags.Status)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(context.Background(), "GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+deps.APIToken)
	req.Header.Set("Accept", "application/json")

	resp, err := deps.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("list request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("list: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed bundleListResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	for _, b := range parsed.Bundles {
		status := b.Status
		if status == "" {
			status = flags.Status
		}
		fmt.Fprintf(deps.Out, "%s\t%s\t%s\n", b.ID, status, b.TargetHost)
	}
	return nil
}

// reRecordRequestBody mirrors the controlplane handler's request struct.
type reRecordRequestBody struct {
	Reason string `json:"reason,omitempty"`
}

type reRecordResponseBody struct {
	NewBundleID string `json:"new_bundle_id"`
	Status      string `json:"status"`
}

// runBundlesReRecord posts to POST /api/v1/dast/bundles/{id}/re-record,
// prints the new draft id, and (if --start-recording is set) prints the
// follow-on command the operator should run.
func runBundlesReRecord(args []string, deps BundlesDeps) error {
	flags, err := parseReRecordFlags(args)
	if err != nil {
		return err
	}
	if deps.APIToken == "" {
		return fmt.Errorf("SENTINELCORE_TOKEN required")
	}
	body, err := json.Marshal(reRecordRequestBody{Reason: flags.Reason})
	if err != nil {
		return err
	}
	endpoint := deps.APIBase + "/api/v1/dast/bundles/" + flags.BundleID + "/re-record"
	req, err := http.NewRequestWithContext(context.Background(), "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+deps.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := deps.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("re-record request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("re-record: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var parsed reRecordResponseBody
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if parsed.NewBundleID == "" {
		return errors.New("re-record: empty new_bundle_id in response")
	}
	fmt.Fprintf(deps.Out, "%s\n", parsed.NewBundleID)
	if flags.StartRecording {
		fmt.Fprintf(deps.Err,
			"Next: sentinelcore-cli dast record --bundle %s\n",
			parsed.NewBundleID)
	}
	return nil
}
