package testutil

import (
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// NewTestNATS starts an in-process NATS server with JetStream enabled
// and returns a client connection. The server is shut down on test cleanup.
func NewTestNATS(t *testing.T) *nats.Conn {
	t.Helper()

	opts := &natsserver.Options{
		Host:      "127.0.0.1",
		Port:      -1, // random available port
		NoLog:     true,
		NoSigs:    true,
		JetStream: true,
		StoreDir:  t.TempDir(),
	}

	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("testutil.NewTestNATS: create server: %v", err)
	}

	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("testutil.NewTestNATS: server not ready")
	}

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		srv.Shutdown()
		t.Fatalf("testutil.NewTestNATS: connect: %v", err)
	}

	t.Cleanup(func() {
		nc.Close()
		srv.Shutdown()
	})

	return nc
}
