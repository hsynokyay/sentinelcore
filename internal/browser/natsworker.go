package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

// NATSBrowserScanJob is the wire format for browser DAST jobs received via NATS.
type NATSBrowserScanJob struct {
	ScanJobID     string              `json:"scan_job_id"`
	ProjectID     string              `json:"project_id"`
	TargetBaseURL string              `json:"target_base_url"`
	SeedURLs      []string            `json:"seed_urls"`
	AllowedHosts  []string            `json:"allowed_hosts"`
	PinnedIPs     map[string][]string `json:"pinned_ips"`
	AuthConfig    *AuthConfigWire     `json:"auth_config,omitempty"`
	MaxURLs       int                 `json:"max_urls"`
	MaxDepth      int                 `json:"max_depth"`
	MaxDuration   string              `json:"max_duration,omitempty"`
	PageTimeout   string              `json:"page_timeout,omitempty"`
}

// AuthConfigWire is the NATS wire format for auth configuration.
type AuthConfigWire struct {
	Strategy    string            `json:"strategy"`
	Credentials map[string]string `json:"credentials"`
	Endpoint    string            `json:"endpoint"`
	ExtraParams map[string]string `json:"extra_params"`
	TTL         string            `json:"ttl"`
}

// NATSBrowserWorker wraps BrowserWorker with NATS JetStream message handling.
type NATSBrowserWorker struct {
	worker     *BrowserWorker
	js         jetstream.JetStream
	signingKey []byte
	logger     zerolog.Logger
}

// NewNATSBrowserWorker creates a NATS-connected browser worker.
func NewNATSBrowserWorker(js jetstream.JetStream, worker *BrowserWorker, signingKey []byte, logger zerolog.Logger) *NATSBrowserWorker {
	return &NATSBrowserWorker{
		worker:     worker,
		js:         js,
		signingKey: signingKey,
		logger:     logger.With().Str("component", "browser-nats-worker").Logger(),
	}
}

// Start begins consuming browser DAST scan jobs from NATS JetStream.
// Blocks until ctx is cancelled.
func (nw *NATSBrowserWorker) Start(ctx context.Context) error {
	cons, err := nw.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "dast-browser-worker",
		FilterSubject: "scan.dast.browser.dispatch",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	nw.logger.Info().Msg("browser DAST worker waiting for scan jobs...")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}

		for msg := range msgs.Messages() {
			var job NATSBrowserScanJob
			if err := json.Unmarshal(msg.Data(), &job); err != nil {
				nw.logger.Error().Err(err).Msg("invalid browser scan job")
				msg.Ack()
				continue
			}

			nw.logger.Info().Str("scan_id", job.ScanJobID).Str("target", job.TargetBaseURL).Msg("processing browser scan")
			nw.processScan(ctx, job)
			msg.Ack()
		}
	}
}

func (nw *NATSBrowserWorker) processScan(ctx context.Context, natsJob NATSBrowserScanJob) {
	nw.publishStatus(ctx, natsJob.ScanJobID, "running", "")

	// Parse durations.
	var maxDuration, pageTimeout time.Duration
	if natsJob.MaxDuration != "" {
		maxDuration, _ = time.ParseDuration(natsJob.MaxDuration)
	}
	if maxDuration == 0 {
		maxDuration = 30 * time.Minute
	}
	if natsJob.PageTimeout != "" {
		pageTimeout, _ = time.ParseDuration(natsJob.PageTimeout)
	}
	if pageTimeout == 0 {
		pageTimeout = 30 * time.Second
	}

	// Build internal job.
	scanJob := BrowserScanJob{
		ID:            natsJob.ScanJobID,
		ProjectID:     natsJob.ProjectID,
		TargetBaseURL: natsJob.TargetBaseURL,
		SeedURLs:      natsJob.SeedURLs,
		AllowedHosts:  natsJob.AllowedHosts,
		PinnedIPs:     natsJob.PinnedIPs,
		MaxURLs:       natsJob.MaxURLs,
		MaxDepth:      natsJob.MaxDepth,
		MaxDuration:   maxDuration,
		PageTimeout:   pageTimeout,
	}

	// Convert auth config if present.
	if natsJob.AuthConfig != nil {
		var ttl time.Duration
		if natsJob.AuthConfig.TTL != "" {
			ttl, _ = time.ParseDuration(natsJob.AuthConfig.TTL)
		}
		scanJob.AuthConfig = &authbroker.AuthConfig{
			Strategy:    natsJob.AuthConfig.Strategy,
			Credentials: natsJob.AuthConfig.Credentials,
			Endpoint:    natsJob.AuthConfig.Endpoint,
			ExtraParams: natsJob.AuthConfig.ExtraParams,
			TTL:         ttl,
		}
	}

	result, err := nw.worker.ExecuteScan(ctx, scanJob)
	if err != nil {
		nw.publishStatus(ctx, natsJob.ScanJobID, "failed", err.Error())
		return
	}

	// Publish findings.
	for _, f := range result.Findings {
		findingData := map[string]any{
			"scan_job_id":  natsJob.ScanJobID,
			"project_id":   natsJob.ProjectID,
			"finding_type": "dast-browser",
			"rule_id":      f.RuleID,
			"title":        f.Title,
			"category":     f.Category,
			"severity":     f.Severity,
			"confidence":   f.Confidence,
			"url":          f.URL,
			"method":       f.Method,
			"match_detail": f.MatchDetail,
		}
		if f.Evidence != nil {
			findingData["evidence_sha256"] = f.Evidence.SHA256
		}

		data, _ := json.Marshal(findingData)
		sig := sc_nats.SignMessage(nw.signingKey, data)

		msg := &natsgo.Msg{
			Subject: "scan.results.dast",
			Data:    data,
			Header:  natsgo.Header{"X-Signature": []string{sig}},
		}
		nw.js.PublishMsg(ctx, msg)
	}

	nw.publishStatus(ctx, natsJob.ScanJobID, result.Status, result.Error)
}

func (nw *NATSBrowserWorker) publishStatus(ctx context.Context, scanID, status, errorMsg string) {
	data, _ := json.Marshal(map[string]string{
		"scan_job_id": scanID,
		"status":      status,
		"error":       errorMsg,
		"worker_type": "dast-browser",
	})
	sig := sc_nats.SignMessage(nw.signingKey, data)
	msg := &natsgo.Msg{
		Subject: "scan.status.update",
		Data:    data,
		Header:  natsgo.Header{"X-Signature": []string{sig}},
	}
	nw.js.PublishMsg(ctx, msg)
}
