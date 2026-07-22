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
// makes a crash safe. Dispatch then publishes the committed intent itself, so
// this loop is NOT the delivery path — it exists for what that publish could
// not finish: a process that died between the commit and the publish, a
// transport outage, a delivery a dead replica had claimed. This loop is the
// only thing that closes that window.
//
// It can publish the same intent TWICE, and that is by design, not an
// oversight. The publish and the published-stamp are separate, non-atomic
// operations: a crash after the transport accepted the intent but before the
// stamp committed leaves the row pending, and the next drain republishes the
// identical message. What that duplicate cannot do is produce a second SIDE
// EFFECT — the message carries the dispatch ref as its dedup id, and the
// connector absorbs the redelivery at its dispatched->executing barrier and its
// dispatch_ref inbox (see worker.executeAndComplete).
//
// The one-use grant does NOT make this safe on its own: it is consumed once at
// dispatch and says nothing about how many times the resulting intent was put
// on the wire.
//
// Concurrent pumps are safe: each row is claimed FOR UPDATE SKIP LOCKED for the
// duration of its publish, so N replicas divide the outbox instead of each
// publishing all of it.
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
