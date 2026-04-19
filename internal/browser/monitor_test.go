package browser

import (
	"context"
	"testing"

	"github.com/chromedp/cdproto/network"
	"github.com/rs/zerolog"
	"github.com/sentinelcore/sentinelcore/pkg/scope"
)

func TestMonitor_IPViolation(t *testing.T) {
	enforcer := newTestEnforcer([]string{"example.com"})
	monitor := NewMonitor(enforcer, zerolog.Nop(), 5)

	// Simulate a response from a blocked private IP.
	ev := &network.EventResponseReceived{
		Response: &network.Response{
			URL:             "https://example.com/page",
			RemoteIPAddress: "192.168.1.1",
		},
	}
	monitor.handleResponseReceived(ev)

	if monitor.Violations() != 1 {
		t.Errorf("expected 1 violation after private IP response, got %d", monitor.Violations())
	}

	// Public IP should not trigger a violation.
	ev2 := &network.EventResponseReceived{
		Response: &network.Response{
			URL:             "https://example.com/page",
			RemoteIPAddress: "93.184.216.34",
		},
	}
	monitor.handleResponseReceived(ev2)

	if monitor.Violations() != 1 {
		t.Errorf("expected violations to remain 1 after public IP, got %d", monitor.Violations())
	}
}

func TestMonitor_AbortThreshold(t *testing.T) {
	enforcer := newTestEnforcer([]string{"example.com"})
	monitor := NewMonitor(enforcer, zerolog.Nop(), 3)

	if monitor.IsAborted() {
		t.Error("should not be aborted before any violations")
	}

	// Trigger 3 violations to reach threshold.
	for i := 0; i < 3; i++ {
		ev := &network.EventResponseReceived{
			Response: &network.Response{
				URL:             "https://example.com/",
				RemoteIPAddress: "10.0.0.1",
			},
		}
		monitor.handleResponseReceived(ev)
	}

	if !monitor.IsAborted() {
		t.Error("should be aborted after reaching threshold")
	}
}

func TestMonitor_WebSocketViolation(t *testing.T) {
	enforcer := newTestEnforcer([]string{"example.com"})
	monitor := NewMonitor(enforcer, zerolog.Nop(), 10)

	// Out-of-scope WebSocket.
	ev := &network.EventWebSocketCreated{
		URL: "wss://evil.com/stream",
	}
	monitor.handleWebSocketCreated(context.Background(), ev)

	if monitor.Violations() != 1 {
		t.Errorf("expected 1 violation for out-of-scope WebSocket, got %d", monitor.Violations())
	}
}

func TestMonitor_ZeroThresholdNeverAborts(t *testing.T) {
	enforcer := scope.NewEnforcer(scope.Config{AllowedHosts: []string{"a.com"}}, zerolog.Nop())
	monitor := NewMonitor(enforcer, zerolog.Nop(), 0)

	// Even with violations, a threshold of 0 should never abort.
	monitor.violations.Store(100)
	if monitor.IsAborted() {
		t.Error("threshold 0 should never cause abort")
	}
}
