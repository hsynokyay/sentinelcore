package correlation

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"

	corr "github.com/sentinelcore/sentinelcore/pkg/correlation"
	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
)

// NATSHandler consumes scan completion events and raw findings from NATS,
// runs the correlation pipeline, and publishes correlated results.
type NATSHandler struct {
	engine     *Engine
	js         jetstream.JetStream
	signingKey []byte
	logger     zerolog.Logger
}

// NewNATSHandler creates a NATS-connected correlation handler.
func NewNATSHandler(engine *Engine, js jetstream.JetStream, signingKey []byte, logger zerolog.Logger) *NATSHandler {
	return &NATSHandler{
		engine:     engine,
		js:         js,
		signingKey: signingKey,
		logger:     logger.With().Str("component", "correlation-nats").Logger(),
	}
}

// Start begins consuming scan results and status updates. Blocks until ctx is cancelled.
func (h *NATSHandler) Start(ctx context.Context) error {
	// Consumer for SAST results
	sastCons, err := h.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "correlation-sast",
		FilterSubject: "scan.results.sast",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create SAST consumer: %w", err)
	}

	// Consumer for DAST results
	dastCons, err := h.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "correlation-dast",
		FilterSubject: "scan.results.dast",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create DAST consumer: %w", err)
	}

	// Consumer for scan status updates (triggers correlation on completion)
	statusCons, err := h.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "correlation-status",
		FilterSubject: "scan.status.update",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create status consumer: %w", err)
	}

	h.logger.Info().Msg("correlation engine waiting for findings...")

	// Accumulate findings per scan job, trigger on completion
	accumulator := newScanAccumulator()

	// Process all streams concurrently
	go h.consumeFindings(ctx, sastCons, accumulator, corr.TypeSAST)
	go h.consumeFindings(ctx, dastCons, accumulator, corr.TypeDAST)

	// Main loop: watch for scan completions
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		msgs, err := statusCons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}

		for msg := range msgs.Messages() {
			var status struct {
				ScanJobID string `json:"scan_job_id"`
				Status    string `json:"status"`
			}
			if err := json.Unmarshal(msg.Data(), &status); err != nil {
				msg.Ack()
				continue
			}

			if status.Status == "completed" {
				h.triggerCorrelation(ctx, accumulator, status.ScanJobID)
			}
			msg.Ack()
		}
	}
}

func (h *NATSHandler) consumeFindings(ctx context.Context, cons jetstream.Consumer, acc *scanAccumulator, findingType corr.FindingType) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := cons.Fetch(10, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}

		for msg := range msgs.Messages() {
			var raw map[string]any
			if err := json.Unmarshal(msg.Data(), &raw); err != nil {
				msg.Ack()
				continue
			}

			finding := mapToRawFinding(raw, findingType)
			if finding != nil {
				acc.add(finding.ScanJobID, finding)
			}
			msg.Ack()
		}
	}
}

func (h *NATSHandler) triggerCorrelation(ctx context.Context, acc *scanAccumulator, scanJobID string) {
	findings := acc.drain(scanJobID)
	if len(findings) == 0 {
		h.logger.Debug().Str("scan_job_id", scanJobID).Msg("no findings to correlate")
		return
	}

	// Determine project ID from first finding
	projectID := findings[0].ProjectID

	run, err := h.engine.ProcessScan(ctx, scanJobID, projectID, findings)
	if err != nil {
		h.logger.Error().Err(err).Str("scan_job_id", scanJobID).Msg("correlation failed")
		return
	}

	// Publish signed correlation result
	data, _ := json.Marshal(run)
	sig := sc_nats.SignMessage(h.signingKey, data)
	msg := &natsgo.Msg{
		Subject: "findings.correlated",
		Data:    data,
		Header:  natsgo.Header{"X-Signature": []string{sig}},
	}
	h.js.PublishMsg(ctx, msg)
}

// mapToRawFinding converts a NATS finding message to a RawFinding.
func mapToRawFinding(raw map[string]any, findingType corr.FindingType) *corr.RawFinding {
	f := &corr.RawFinding{
		Type:    findingType,
		FoundAt: time.Now(),
	}

	if v, ok := raw["scan_job_id"].(string); ok {
		f.ScanJobID = v
	}
	if v, ok := raw["project_id"].(string); ok {
		f.ProjectID = v
	}
	if v, ok := raw["rule_id"].(string); ok {
		f.RuleID = v
	}
	if v, ok := raw["title"].(string); ok {
		f.Title = v
	}
	if v, ok := raw["severity"].(string); ok {
		f.Severity = v
	}
	if v, ok := raw["confidence"].(string); ok {
		f.Confidence = v
	}
	if v, ok := raw["cwe_id"].(float64); ok {
		f.CWEID = int(v)
	}

	// SAST fields
	if v, ok := raw["file_path"].(string); ok {
		f.FilePath = v
	}
	if v, ok := raw["line_start"].(float64); ok {
		f.LineStart = int(v)
	}
	if v, ok := raw["code_snippet"].(string); ok {
		f.CodeSnippet = v
	}
	if v, ok := raw["fingerprint"].(string); ok {
		f.Fingerprint = v
	}

	// DAST fields
	if v, ok := raw["url"].(string); ok {
		f.URL = v
	}
	if v, ok := raw["method"].(string); ok {
		f.Method = v
	}
	if v, ok := raw["category"].(string); ok {
		f.Category = v
	}

	if f.ID == "" {
		f.ID = f.ScanJobID + "-" + f.RuleID
	}

	return f
}

// scanAccumulator collects findings per scan job until the scan completes.
type scanAccumulator struct {
	mu    sync.Mutex
	scans map[string][]*corr.RawFinding
}

func newScanAccumulator() *scanAccumulator {
	return &scanAccumulator{scans: make(map[string][]*corr.RawFinding)}
}

func (a *scanAccumulator) add(scanJobID string, f *corr.RawFinding) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.scans[scanJobID] = append(a.scans[scanJobID], f)
}

func (a *scanAccumulator) drain(scanJobID string) []*corr.RawFinding {
	a.mu.Lock()
	defer a.mu.Unlock()
	findings := a.scans[scanJobID]
	delete(a.scans, scanJobID)
	return findings
}
