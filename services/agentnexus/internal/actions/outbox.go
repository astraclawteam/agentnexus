package actions

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"time"
)

// DispatchMessage is the durable dispatch intent published to the connector
// transport. It binds the exact operation (capability + parameter_hash) and the
// one-use grant; it never carries connector topology, trusted identity or a
// business Outcome.
//
// DispatchRef is also the message's DEDUP ID: every delivery attempt of the
// same intent carries the same ref, the transport publishes it as the message
// id, and the connector worker uses it as the durable inbox key. That is what
// makes an at-least-once redelivery of an identical message safe.
type DispatchMessage struct {
	TenantRef     string       `json:"tenant_ref"`
	ActionRef     string       `json:"action_ref"`
	DispatchRef   string       `json:"dispatch_ref"`
	Capability    string       `json:"capability"`
	ParameterHash string       `json:"parameter_hash"`
	GrantRef      string       `json:"grant_ref"`
	Kind          DispatchKind `json:"kind"`
}

// DecodeDispatchMessage strictly decodes one durable dispatch intent delivered on
// SubjectActionDispatch (the central Connector Worker consumes these). Unknown
// members and trailing data are rejected so a malformed or hostile transport
// payload never silently decodes into a partially-populated intent that could be
// misread as a legitimate dispatch.
func DecodeDispatchMessage(data []byte) (DispatchMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var message DispatchMessage
	if err := decoder.Decode(&message); err != nil {
		return DispatchMessage{}, err
	}
	if decoder.More() {
		return DispatchMessage{}, errors.New("trailing data after dispatch message")
	}
	return message, nil
}

// Publisher is the outbox dispatch transport port. The transactional outbox row
// is written atomically with the granted->dispatched transition; the Publisher
// then delivers the durable intent to the connector host (NATS JetStream). A
// publish failure leaves the outbox row pending for the recovery pump — it never
// re-dispatches a second side effect.
type Publisher interface {
	PublishDispatch(ctx context.Context, message DispatchMessage) error
}

// Delivery bounds of the transactional outbox.
const (
	// maxDispatchAttempts is where the drain GIVES UP on an intent. Without a
	// bound, a permanently unpublishable row is retried forever and — because
	// the drain reads oldest-first — the intents behind it inherit its latency.
	maxDispatchAttempts = 8
	// dispatchRetryBaseDelay is the first backoff after a failed attempt; each
	// further attempt doubles it up to dispatchRetryMaxDelay.
	dispatchRetryBaseDelay = 5 * time.Second
	// dispatchRetryMaxDelay caps the backoff so a long outage still recovers
	// within a bounded time of the transport coming back.
	dispatchRetryMaxDelay = 5 * time.Minute
	// defaultDispatchClaimBatch bounds ONE drain pass.
	defaultDispatchClaimBatch = 1000
)

// dispatchRetryDelay is the backoff after `attempts` failed delivery attempts:
// exponential from dispatchRetryBaseDelay, capped at dispatchRetryMaxDelay.
func dispatchRetryDelay(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	delay := dispatchRetryBaseDelay
	for i := 1; i < attempts; i++ {
		delay *= 2
		if delay >= dispatchRetryMaxDelay {
			return dispatchRetryMaxDelay
		}
	}
	return delay
}

// deliver publishes ONE claimed dispatch intent and decides what the store must
// record about the attempt. It is called with the outbox row lock held.
//
// A failed attempt is never fatal to the drain: it is counted, backed off and —
// once the intent has burned maxDispatchAttempts — dead lettered, so the intents
// behind it keep flowing and the undelivered one stays visible instead of
// silently cycling forever.
func (s *Service) deliver(ctx context.Context, dispatch Dispatch) DispatchOutcome {
	message := DispatchMessage{
		TenantRef:     dispatch.TenantRef,
		ActionRef:     dispatch.ActionRef,
		DispatchRef:   dispatch.DispatchRef,
		Capability:    dispatch.Capability,
		ParameterHash: dispatch.ParameterHash,
		GrantRef:      dispatch.GrantRef,
		Kind:          dispatch.Kind,
	}
	err := s.publisher.PublishDispatch(ctx, message)
	if err == nil {
		return DispatchOutcome{Published: true}
	}
	attempts := dispatch.Attempts + 1
	outcome := DispatchOutcome{LastError: err.Error()}
	if attempts >= maxDispatchAttempts {
		outcome.DeadLetter = true
		s.logger.ErrorContext(ctx, "action outbox dispatch dead lettered",
			slog.String("tenant_ref", dispatch.TenantRef),
			slog.String("action_ref", dispatch.ActionRef),
			slog.String("dispatch_ref", dispatch.DispatchRef),
			slog.Int("attempts", attempts),
			slog.String("error", err.Error()))
		return outcome
	}
	outcome.NextAttemptAt = s.now().UTC().Add(dispatchRetryDelay(attempts))
	s.logger.WarnContext(ctx, "action outbox dispatch publish failed",
		slog.String("tenant_ref", dispatch.TenantRef),
		slog.String("action_ref", dispatch.ActionRef),
		slog.String("dispatch_ref", dispatch.DispatchRef),
		slog.Int("attempts", attempts),
		slog.Time("next_attempt_at", outcome.NextAttemptAt),
		slog.String("error", err.Error()))
	return outcome
}

// publishDispatched delivers the intent the caller's Dispatch just committed.
//
// This is the ORDINARY delivery path. The outbox row is committed first so a
// crash cannot lose the intent, but committing it is not delivering it: without
// this call the intent would sit in the outbox until the recovery pump's next
// tick, which would make a background recovery loop the only thing that ever
// reaches the connector.
//
// It goes through the SAME row claim the pump uses, so a pump tick racing this
// publish skips the row instead of publishing it a second time. A failure here
// is deliberately not returned to the caller: the action IS dispatched (the
// one-use grant is consumed and the row is durable), so surfacing an error
// would only invite a blind re-dispatch that ErrBlindRetryForbidden then
// rejects. The pump owns the retry.
func (s *Service) publishDispatched(ctx context.Context, tenantRef, dispatchRef string) {
	if s.publisher == nil {
		s.logger.WarnContext(ctx, "action dispatched with no publisher wired; the intent stays pending in the outbox",
			slog.String("tenant_ref", tenantRef), slog.String("dispatch_ref", dispatchRef))
		return
	}
	claimed, err := s.store.ClaimDispatch(ctx, tenantRef, dispatchRef, s.now().UTC(), s.deliver)
	if err != nil {
		s.logger.ErrorContext(ctx, "action outbox dispatch claim failed; the intent stays pending for the recovery pump",
			slog.String("tenant_ref", tenantRef), slog.String("dispatch_ref", dispatchRef), slog.String("error", err.Error()))
		return
	}
	if !claimed {
		// A concurrent pump holds the row, or already delivered it. Either way
		// the intent is accounted for; publishing it here too would be the
		// duplicate this claim exists to prevent.
		s.logger.DebugContext(ctx, "action outbox dispatch already claimed elsewhere",
			slog.String("tenant_ref", tenantRef), slog.String("dispatch_ref", dispatchRef))
	}
}

// RepublishPending is the CRASH-WINDOW RECOVERY of the transactional outbox, not
// the delivery path: Dispatch publishes its own intent right after the commit.
// This drains whatever that publish never got to — a process that died between
// the outbox commit and the publish, a transport outage, a delivery another
// replica started and lost — and it is the only thing that closes that window.
//
// It claims each eligible row under FOR UPDATE SKIP LOCKED, so N replicas
// running this concurrently divide the outbox instead of each publishing all of
// it. Returns the number of intents published.
//
// AT-LEAST-ONCE, not exactly-once: the publish and the published stamp are
// separate operations, so a crash after the transport accepted the intent but
// before the stamp committed republishes the IDENTICAL message on the next
// drain. That duplicate is absorbed downstream, by the dispatch_ref dedup id the
// message carries — see the note on DispatchMessage — not by anything here.
func (s *Service) RepublishPending(ctx context.Context, tenantRef string) (int, error) {
	if err := s.guard(ctx); err != nil {
		return 0, err
	}
	if s.publisher == nil {
		return 0, errors.Join(ErrUnavailable, errors.New("no dispatch publisher wired"))
	}
	published := 0
	_, err := s.store.ClaimPendingDispatches(ctx, tenantRef, 0, s.now().UTC(), func(ctx context.Context, dispatch Dispatch) DispatchOutcome {
		outcome := s.deliver(ctx, dispatch)
		if outcome.Published {
			published++
		}
		return outcome
	})
	if err != nil {
		return published, errors.Join(ErrUnavailable, err)
	}
	return published, nil
}

func randomOpaqueID(prefix string) string {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}
