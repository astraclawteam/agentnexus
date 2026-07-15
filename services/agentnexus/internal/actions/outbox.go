package actions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// DispatchMessage is the durable dispatch intent published to the connector
// transport. It binds the exact operation (capability + parameter_hash) and the
// one-use grant; it never carries connector topology, trusted identity or a
// business Outcome.
type DispatchMessage struct {
	TenantRef     string       `json:"tenant_ref"`
	ActionRef     string       `json:"action_ref"`
	DispatchRef   string       `json:"dispatch_ref"`
	Capability    string       `json:"capability"`
	ParameterHash string       `json:"parameter_hash"`
	GrantRef      string       `json:"grant_ref"`
	Kind          DispatchKind `json:"kind"`
}

// Publisher is the outbox dispatch transport port. The transactional outbox row
// is written atomically with the granted->dispatched transition; the Publisher
// then delivers the durable intent to the connector host (NATS JetStream). A
// publish failure leaves the outbox row pending for the recovery pump — it never
// re-dispatches a second side effect.
type Publisher interface {
	PublishDispatch(ctx context.Context, message DispatchMessage) error
}

// RepublishPending is the recovery pump of the transactional outbox: it
// republishes every durable dispatch intent that was written but not yet
// delivered (a crash before publish), then marks each published. It NEVER
// re-dispatches an already-published or consumed action — the one-use grant was
// consumed in the same transaction that wrote the outbox row, so a second
// dispatch is impossible. Returns the number of intents published.
func (s *Service) RepublishPending(ctx context.Context, tenantRef string) (int, error) {
	if err := s.guard(ctx); err != nil {
		return 0, err
	}
	if s.publisher == nil {
		return 0, errors.Join(ErrUnavailable, errors.New("no dispatch publisher wired"))
	}
	pending, err := s.store.PendingDispatches(ctx, tenantRef, 0)
	if err != nil {
		return 0, errors.Join(ErrUnavailable, err)
	}
	published := 0
	for _, dispatch := range pending {
		message := DispatchMessage{
			TenantRef:     dispatch.TenantRef,
			ActionRef:     dispatch.ActionRef,
			DispatchRef:   dispatch.DispatchRef,
			Capability:    dispatch.Capability,
			ParameterHash: dispatch.ParameterHash,
			GrantRef:      dispatch.GrantRef,
			Kind:          dispatch.Kind,
		}
		if err := s.publisher.PublishDispatch(ctx, message); err != nil {
			return published, errors.Join(ErrUnavailable, err)
		}
		if err := s.store.MarkDispatchPublished(ctx, tenantRef, dispatch.DispatchRef, s.now().UTC()); err != nil {
			return published, errors.Join(ErrUnavailable, err)
		}
		published++
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
