package dast

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/authbroker"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// NATSScanJob is the wire format for DAST scan jobs received via NATS.
type NATSScanJob struct {
	ScanJobID     string              `json:"scan_job_id"`
	ProjectID     string              `json:"project_id"`
	TargetBaseURL string              `json:"target_base_url"`
	AllowedHosts  []string            `json:"allowed_hosts"`
	PinnedIPs     map[string][]string `json:"pinned_ips"`
	Endpoints     []Endpoint          `json:"endpoints"`
	AuthConfig    *authbroker.AuthConfig `json:"auth_config,omitempty"`
	Concurrency   int                 `json:"concurrency"`
	RequestDelay  string              `json:"request_delay,omitempty"` // duration string
	MaxViolations int                 `json:"max_violations"`
}

// NATSWorker wraps the DAST Worker with NATS JetStream message consumption.
type NATSWorker struct {
	worker     *Worker
	js         jetstream.JetStream
	signingKey []byte
	logger     zerolog.Logger
}

// NewNATSWorker creates a NATS-connected DAST worker.
func NewNATSWorker(js jetstream.JetStream, worker *Worker, signingKey []byte, logger zerolog.Logger) *NATSWorker {
	return &NATSWorker{
		worker:     worker,
		js:         js,
		signingKey: signingKey,
		logger:     logger.With().Str("component", "dast-nats-worker").Logger(),
	}
}

// Start begins consuming DAST scan jobs from NATS JetStream. Blocks until ctx is cancelled.
func (nw *NATSWorker) Start(ctx context.Context) error {
	cons, err := nw.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "dast-worker",
		FilterSubject: "scan.dast.dispatch",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	nw.logger.Info().Msg("DAST worker waiting for scan jobs...")

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
			var job NATSScanJob
			if err := json.Unmarshal(msg.Data(), &job); err != nil {
				nw.logger.Error().Err(err).Msg("invalid DAST scan job")
				msg.Ack()
				continue
			}

			nw.logger.Info().Str("scan_id", job.ScanJobID).Str("target", job.TargetBaseURL).Msg("processing DAST scan")
			nw.processScan(ctx, job)
			msg.Ack()
		}
	}
}

func (nw *NATSWorker) processScan(ctx context.Context, natsJob NATSScanJob) {
	nw.publishStatus(ctx, natsJob.ScanJobID, "running", "")

	// Convert pinned IPs from string to net.IP
	pinnedIPs := make(map[string][]net.IP)
	for host, ipStrs := range natsJob.PinnedIPs {
		for _, ipStr := range ipStrs {
			if ip := net.ParseIP(ipStr); ip != nil {
				pinnedIPs[host] = append(pinnedIPs[host], ip)
			}
		}
	}

	// Parse request delay
	var requestDelay time.Duration
	if natsJob.RequestDelay != "" {
		requestDelay, _ = time.ParseDuration(natsJob.RequestDelay)
	}

	maxViolations := natsJob.MaxViolations
	if maxViolations == 0 {
		maxViolations = 5
	}

	// Build the scan job for the worker
	scanJob := ScanJob{
		ID:            natsJob.ScanJobID,
		TargetBaseURL: natsJob.TargetBaseURL,
		AllowedHosts:  natsJob.AllowedHosts,
		Endpoints:     natsJob.Endpoints,
		AuthConfig:    natsJob.AuthConfig,
		ScopeConfig: scope.Config{
			AllowedHosts:  natsJob.AllowedHosts,
			PinnedIPs:     pinnedIPs,
			MaxViolations: maxViolations,
		},
		Concurrency:  natsJob.Concurrency,
		RequestDelay: requestDelay,
	}

	result, err := nw.worker.ExecuteScan(ctx, scanJob)
	if err != nil {
		nw.publishStatus(ctx, natsJob.ScanJobID, "failed", err.Error())
		return
	}

	// Publish findings
	for _, f := range result.Findings {
		findingData := map[string]any{
			"scan_job_id":  natsJob.ScanJobID,
			"project_id":   natsJob.ProjectID,
			"finding_type": "dast",
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

func (nw *NATSWorker) publishStatus(ctx context.Context, scanID, status, errorMsg string) {
	data, _ := json.Marshal(map[string]string{
		"scan_job_id": scanID,
		"status":      status,
		"error":       errorMsg,
		"worker_type": "dast",
	})
	sig := sc_nats.SignMessage(nw.signingKey, data)
	msg := &natsgo.Msg{
		Subject: "scan.status.update",
		Data:    data,
		Header:  natsgo.Header{"X-Signature": []string{sig}},
	}
	nw.js.PublishMsg(ctx, msg)
}
