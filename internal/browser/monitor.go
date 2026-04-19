package browser

import (
	"context"
	"net"
	"strings"
	"sync/atomic"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/network"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

// Monitor implements Layer 3 detection by observing CDP network events
// and validating remote IP addresses against blocked CIDRs.
type Monitor struct {
	enforcer       *scope.Enforcer
	logger         zerolog.Logger
	violations     atomic.Int64
	abortThreshold int
}

// NewMonitor creates a network monitor for Layer 3 scope detection.
// abortThreshold is the number of violations after which the scan should be aborted.
func NewMonitor(enforcer *scope.Enforcer, logger zerolog.Logger, abortThreshold int) *Monitor {
	return &Monitor{
		enforcer:       enforcer,
		logger:         logger.With().Str("component", "cdp-monitor").Logger(),
		abortThreshold: abortThreshold,
	}
}

// Violations returns the total number of detected violations.
func (m *Monitor) Violations() int64 {
	return m.violations.Load()
}

// IsAborted returns true if the violation count has reached or exceeded
// the abort threshold.
func (m *Monitor) IsAborted() bool {
	return m.abortThreshold > 0 && int(m.violations.Load()) >= m.abortThreshold
}

// Enable sets up CDP event listeners for Network.responseReceived and
// Network.webSocketCreated events. It validates remote IPs against blocked
// CIDRs and WebSocket URLs against the scope enforcer.
func (m *Monitor) Enable(ctx context.Context) error {
	// Enable the Network domain to receive events.
	if err := network.Enable().Do(ctx); err != nil {
		return err
	}

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			m.handleResponseReceived(e)
		case *network.EventWebSocketCreated:
			m.handleWebSocketCreated(ctx, e)
		}
	})

	m.logger.Info().Int("abort_threshold", m.abortThreshold).Msg("CDP network monitor enabled")
	return nil
}

// handleResponseReceived validates the remoteIPAddress field against blocked CIDRs.
func (m *Monitor) handleResponseReceived(ev *network.EventResponseReceived) {
	remoteIP := ev.Response.RemoteIPAddress
	if remoteIP == "" {
		return
	}

	// Strip brackets from IPv6 addresses (e.g., "[::1]" -> "::1").
	remoteIP = strings.TrimPrefix(remoteIP, "[")
	remoteIP = strings.TrimSuffix(remoteIP, "]")

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return
	}

	if scope.IsBlockedIP(ip) {
		m.violations.Add(1)
		m.logger.Error().
			Str("remote_ip", remoteIP).
			Str("url", ev.Response.URL).
			Int64("violations", m.violations.Load()).
			Msg("Layer 3: response from blocked IP detected")
	}
}

// handleWebSocketCreated validates the WebSocket URL against the scope enforcer.
func (m *Monitor) handleWebSocketCreated(ctx context.Context, ev *network.EventWebSocketCreated) {
	wsURL := ev.URL
	if wsURL == "" {
		return
	}

	// The scope enforcer handles ws/wss normalization internally.
	if err := m.enforcer.CheckRequest(ctx, wsURL); err != nil {
		m.violations.Add(1)
		m.logger.Error().
			Str("ws_url", wsURL).
			Err(err).
			Int64("violations", m.violations.Load()).
			Msg("Layer 3: out-of-scope WebSocket connection detected")
	}
}
