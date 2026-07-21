package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// DispatchConfig locates the message bus the transactional outbox delivers
// durable dispatch intents on.
//
// It is OPTIONAL on purpose. Without a bus the gateway still serves the
// browser, authorization and audit surfaces and still commits every outbox
// row; what stops is delivery, so Actions reach `dispatched` and go no
// further. That is a visibly degraded deployment rather than a silently
// broken one, and it keeps a browser-only or audit-only environment runnable.
type DispatchConfig struct {
	// NATSURL is empty when no bus is configured.
	NATSURL string
	// RecoveryInterval paces the outbox recovery drain; zero selects the
	// composition default.
	RecoveryInterval time.Duration
	// StreamName is the JetStream stream carrying dispatch intents.
	StreamName string
}

// DefaultDispatchStream is the JetStream stream dispatch intents live on.
const DefaultDispatchStream = "AGENTNEXUS_ACTIONS"

// Enabled reports whether a dispatch transport is configured.
func (c DispatchConfig) Enabled() bool { return c.NATSURL != "" }

// LoadDispatch reads the dispatch transport settings. A malformed interval is
// an error rather than a silent fallback: a deployment that meant to slow the
// recovery drain must not get the default without being told.
func LoadDispatch() (DispatchConfig, error) {
	cfg := DispatchConfig{
		NATSURL:    strings.TrimSpace(os.Getenv("AGENTNEXUS_NATS_URL")),
		StreamName: strings.TrimSpace(os.Getenv("AGENTNEXUS_DISPATCH_STREAM")),
	}
	if cfg.StreamName == "" {
		cfg.StreamName = DefaultDispatchStream
	}
	raw := strings.TrimSpace(os.Getenv("AGENTNEXUS_DISPATCH_RECOVERY_SECONDS"))
	if raw == "" {
		return cfg, nil
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return DispatchConfig{}, errors.New("AGENTNEXUS_DISPATCH_RECOVERY_SECONDS must be a positive integer number of seconds")
	}
	cfg.RecoveryInterval = time.Duration(seconds) * time.Second
	return cfg, nil
}
