package sc_nats

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Config holds NATS connection parameters.
type Config struct {
	URL string `env:"NATS_URL" default:"nats://localhost:4222"`
}

// Connect establishes a NATS connection and returns both the connection and a JetStream context.
func Connect(cfg Config) (*nats.Conn, jetstream.JetStream, error) {
	nc, err := nats.Connect(cfg.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("sc_nats.Connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, nil, fmt.Errorf("sc_nats.Connect: jetstream: %w", err)
	}

	return nc, js, nil
}

// EnsureStreams creates the required JetStream streams if they don't exist.
func EnsureStreams(ctx context.Context, js jetstream.JetStream) error {
	streams := []jetstream.StreamConfig{
		{Name: "SCANS", Subjects: []string{"scan.>"}, Retention: jetstream.WorkQueuePolicy, MaxAge: 7 * 24 * time.Hour},
		{Name: "FINDINGS", Subjects: []string{"findings.>"}, MaxAge: 7 * 24 * time.Hour},
		{Name: "AUDIT", Subjects: []string{"audit.>"}, MaxAge: 30 * 24 * time.Hour},
		{Name: "VULN", Subjects: []string{"vuln.>"}, MaxAge: 7 * 24 * time.Hour},
		{Name: "GOVERNANCE", Subjects: []string{"governance.>"}, MaxAge: 7 * 24 * time.Hour},
	}
	for _, cfg := range streams {
		_, err := js.CreateOrUpdateStream(ctx, cfg)
		if err != nil {
			return fmt.Errorf("create stream %s: %w", cfg.Name, err)
		}
	}
	return nil
}
