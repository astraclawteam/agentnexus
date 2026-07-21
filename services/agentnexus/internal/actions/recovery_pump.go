package actions

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// PendingRepublisher is the recovery-pump port. *Service implements it.
type PendingRepublisher interface {
	RepublishPending(ctx context.Context, tenantRef string) (int, error)
}

// RecoveryPump drives the transactional outbox's recovery path.
//
// The outbox row is committed in the SAME transaction as the granted->
// dispatched transition, before anything is published. That ordering is what
// makes a crash safe, but it also means a process that dies between commit and
// publish leaves a durable intent that nothing will ever deliver on its own.
// This loop is the only thing that closes that window.
//
// It cannot double-dispatch: the one-use grant was consumed in the transaction
// that wrote the row, so republishing an already-consumed action is impossible
// by construction rather than by this loop being careful.
type RecoveryPump struct {
	republisher PendingRepublisher
	tenantRef   string
	interval    time.Duration
	logger      *slog.Logger
}

// NewRecoveryPump validates the configuration. Every dependency is required:
// a pump with a missing tenant or a non-positive interval would silently never
// recover anything, which is worse than refusing to start.
func NewRecoveryPump(republisher PendingRepublisher, tenantRef string, interval time.Duration) (*RecoveryPump, error) {
	if republisher == nil {
		return nil, errors.New("recovery pump requires a republisher")
	}
	if tenantRef == "" {
		return nil, errors.New("recovery pump requires a tenant reference")
	}
	if interval <= 0 {
		return nil, errors.New("recovery pump requires a positive interval")
	}
	pump := &RecoveryPump{republisher: republisher, tenantRef: tenantRef, interval: interval, logger: slog.Default()}
	return pump, nil
}

// Run drains the outbox immediately, then on every interval, until ctx is done.
// It blocks; callers own the goroutine.
//
// A drain failure is logged and retried on the next tick. Ending the loop on
// error would strand an already-committed intent forever, so a transient
// transport outage must never be fatal here.
func (p *RecoveryPump) Run(ctx context.Context) {
	// Drain on start: a restart must not wait a full interval to deliver
	// intents that were already committed before the crash.
	p.drain(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.drain(ctx)
		}
	}
}

func (p *RecoveryPump) drain(ctx context.Context) {
	published, err := p.republisher.RepublishPending(ctx, p.tenantRef)
	if err != nil {
		if ctx.Err() != nil {
			// Shutdown, not a fault.
			return
		}
		p.logger.ErrorContext(ctx, "action outbox recovery drain failed", "tenant_ref", p.tenantRef, "error", err)
		return
	}
	if published > 0 {
		p.logger.InfoContext(ctx, "action outbox recovery republished pending dispatches", "tenant_ref", p.tenantRef, "published", published)
	}
}
