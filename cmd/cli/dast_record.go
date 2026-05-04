package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/recording"
)

func runDastRecord(args []string) error {
	fs := flag.NewFlagSet("dast record", flag.ContinueOnError)
	target := fs.String("target", "", "URL of the application's login page (required)")
	project := fs.String("project", "", "Project UUID under SentinelCore (required)")
	apiBase := fs.String("api", "https://sentinelcore.resiliencetech.com.tr", "Controlplane base URL")
	apiToken := fs.String("token", "", "API access token (or env SENTINELCORE_TOKEN)")
	headless := fs.Bool("headless", false, "Run Chrome headless (no UI; for CI testing)")
	stopAt := fs.String("stop-at", "", "Optional URL prefix; recording stops when navigation reaches it")
	timeoutMin := fs.Int("timeout", 10, "Hard timeout in minutes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *project == "" {
		fs.Usage()
		return fmt.Errorf("--target and --project are required")
	}
	token := *apiToken
	if token == "" {
		token = os.Getenv("SENTINELCORE_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("--token (or env SENTINELCORE_TOKEN) required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Println("==================================================================")
	fmt.Printf("Starting recording session for %s\n", *target)
	fmt.Printf("Press Ctrl+C in this terminal when you finish logging in.\n")
	if *stopAt != "" {
		fmt.Printf("OR navigate to: %s (recording stops automatically)\n", *stopAt)
	}
	fmt.Println("==================================================================")

	rec := recording.New(recording.Options{
		TargetURL:        *target,
		HeadlessFallback: *headless,
		StopWhenURL:      *stopAt,
		Timeout:          time.Duration(*timeoutMin) * time.Minute,
	})

	session, err := rec.Run(ctx)
	if err != nil {
		return fmt.Errorf("recording failed: %w", err)
	}

	if len(session.Cookies) == 0 {
		return fmt.Errorf("recording captured no cookies — login may not have completed")
	}

	fmt.Printf("\nCaptured %d cookies, %d response headers.\n", len(session.Cookies), len(session.Headers))
	fmt.Printf("Final URL: %s\n", session.FinalURL)
	if session.CaptchaDetected {
		fmt.Println("CAPTCHA detected in flow — bundle will be marked one-shot only.")
	}

	bundleID, err := uploadBundle(ctx, *apiBase, token, *project, session)
	if err != nil {
		return fmt.Errorf("upload bundle: %w", err)
	}
	fmt.Printf("Uploaded as bundle: %s (status: pending_review)\n", bundleID)
	fmt.Println("Have your reviewer approve via /api/v1/dast/bundles/<id>/approve.")
	return nil
}

func uploadBundle(ctx context.Context, apiBase, token, projectID string, session *recording.RecordedSession) (string, error) {
	type cookie struct {
		Name     string `json:"name"`
		Value    string `json:"value"`
		Domain   string `json:"domain,omitempty"`
		Path     string `json:"path,omitempty"`
		HttpOnly bool   `json:"http_only,omitempty"`
		Secure   bool   `json:"secure,omitempty"`
	}
	type sessionCapture struct {
		Cookies []cookie          `json:"cookies"`
		Headers map[string]string `json:"headers"`
	}
	type recordingMeta struct {
		BrowserUserAgent  string `json:"browser_user_agent"`
		RecordedAt        string `json:"recorded_at"`
		RecordingDuration int64  `json:"recording_duration_ms"`
		CaptchaDetected   bool   `json:"captcha_detected"`
		FinalURL          string `json:"final_url"`
	}
	type req struct {
		ProjectID       string           `json:"project_id"`
		TargetHost      string           `json:"target_host"`
		Type            string           `json:"type"`
		CapturedSession sessionCapture   `json:"captured_session"`
		TTLSeconds      int              `json:"ttl_seconds"`
		ACL             []map[string]any `json:"acl"`
		RecordingMetadata recordingMeta  `json:"recording_metadata"`
	}

	cookies := make([]cookie, 0, len(session.Cookies))
	for _, c := range session.Cookies {
		cookies = append(cookies, cookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, Path: c.Path,
			HttpOnly: c.HttpOnly, Secure: c.Secure,
		})
	}

	targetHost := hostFromURL(session.FinalURL)

	body, _ := json.Marshal(req{
		ProjectID: projectID, TargetHost: targetHost, Type: "recorded_login",
		CapturedSession: sessionCapture{Cookies: cookies, Headers: session.Headers},
		TTLSeconds: 86400,
		ACL: []map[string]any{{"project_id": projectID}},
		RecordingMetadata: recordingMeta{
			BrowserUserAgent:  session.BrowserUserAgent,
			RecordedAt:        session.StoppedAt.Format(time.RFC3339Nano),
			RecordingDuration: session.StoppedAt.Sub(session.StartedAt).Milliseconds(),
			CaptchaDetected:   session.CaptchaDetected,
			FinalURL:          session.FinalURL,
		},
	})

	httpReq, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/api/v1/dast/bundles", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("api error %d: %s", resp.StatusCode, string(out))
	}
	var parsed struct {
		BundleID string `json:"bundle_id"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return "", err
	}
	return parsed.BundleID, nil
}

func hostFromURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed == nil {
		return ""
	}
	return parsed.Host
}
