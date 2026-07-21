package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ReadyRunner is the readiness-gated subset of *Worker.
type ReadyRunner interface {
	CheckReady(ctx context.Context) error
	Run(ctx context.Context, source DispatchSource) error
}

// RunWhenReady blocks until the worker reports ready, then hands it the
// dispatch source.
//
// Worker.Run does NOT check readiness: it fetches immediately. That split is
// deliberate, but it means a worker whose binding resolver, receipt signer or
// observation producer is missing would pull real dispatch intents off the
// stream and fail every one of them — turning a deployment gap into redelivery
// churn against durable Actions, and burning their delivery attempts. This gate
// is what keeps CheckReady's contract ("main() must not serve dispatches until
// this returns nil") true in the composed command rather than in a comment.
//
// The gate is a wait, not a fatal error, so a deployment that wires its seams
// while the process is up starts serving without a restart. Startup order
// between the worker and its dependencies stops being something an operator has
// to get right.
func RunWhenReady(ctx context.Context, runner ReadyRunner, source DispatchSource, pollInterval time.Duration, opts ...ReadinessGateOption) error {
	if runner == nil {
		return errors.Join(ErrInvalidConfig, errors.New("readiness gate requires a worker"))
	}
	if source == nil {
		return errors.Join(ErrInvalidConfig, errors.New("readiness gate requires a dispatch source"))
	}
	if pollInterval <= 0 {
		return errors.Join(ErrInvalidConfig, errors.New("readiness gate requires a positive poll interval"))
	}
	gate := &readinessGate{logger: slog.Default()}
	for _, opt := range opts {
		opt(gate)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	var lastReason string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := runner.CheckReady(ctx)
		if err == nil {
			gate.logger.InfoContext(ctx, "worker.ready", slog.String("consumer", DurableName))
			return runner.Run(ctx, source)
		}
		// Log the reason once per distinct cause: a worker parked on a missing
		// seam for hours must stay diagnosable without flooding the log.
		if reason := err.Error(); reason != lastReason {
			lastReason = reason
			gate.logger.WarnContext(ctx, "worker.not_ready_not_consuming", slog.String("consumer", DurableName), slog.String("reason", reason))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type readinessGate struct {
	logger *slog.Logger
}

// ReadinessGateOption configures the readiness gate.
type ReadinessGateOption func(*readinessGate)

// WithReadinessGateLogger overrides the gate's logger.
func WithReadinessGateLogger(logger *slog.Logger) ReadinessGateOption {
	return func(g *readinessGate) {
		if logger != nil {
			g.logger = logger
		}
	}
}
