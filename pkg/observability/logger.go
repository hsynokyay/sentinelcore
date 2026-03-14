package observability

import (
	"os"

	"github.com/rs/zerolog"
)

// NewLogger creates a structured logger for the given service name.
func NewLogger(service string) zerolog.Logger {
	return zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", service).
		Logger()
}
