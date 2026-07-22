package evidence

import (
	"context"
	"errors"
)

// ErrNoContentSource is the fetch failure reported by PendingContentSource. It
// is a deployment fact, not a bug: this build has no path from a registry
// binding's private SourceRef to a real customer system.
var ErrNoContentSource = errors.New("evidence: no content source is configured for this deployment")

// PendingContentSource is the honestly-undelivering ContentSource. It satisfies
// the port so the evidence runtime can be CONSTRUCTED — and therefore so
// /v1/runtime/locate and /v1/runtime/read can be REGISTERED — while every fetch
// fails closed.
//
// Why there is nothing better to wire yet. The ContentSource contract says the
// production implementation is the connector runtime. The connector runtime
// exists (internal/connectors/runtime), but the link from a SourceBinding to it
// does not: fetching real evidence needs a resolver from the binding's private
// SourceRef to a concrete connector manifest, the customer's binding for it, the
// resource/operation to invoke and the credential reference to invoke it with.
// That resolver is task B3. Its result shapes do not line up either — the
// runtime returns Data as map[string]any, not the []Record this port promises —
// so even a hand-wired call would need a normalization contract that nobody has
// written down.
//
// Fetch failures land in Service.resolveNeed as errors.Join(ErrUnavailable,
// "source fetch failed"), which the gateway maps to 503 evidence_unavailable.
// That is the correct report: the plane is up, the source is not.
//
// Do NOT substitute MemoryContentSource here. Its records are whatever a caller
// seeded, so an unseeded source ref errors and a seeded one returns fabricated
// business data that the plane would then stage, hash, seal, audit and serve as
// though a customer system had reported it. Fabricated evidence is worse than no
// evidence: the whole point of this plane is that a handle attests to something
// a real source actually said.
type PendingContentSource struct{}

// NewPendingContentSource builds the no-source-integration content source.
func NewPendingContentSource() *PendingContentSource { return &PendingContentSource{} }

// FetchEvidence always fails closed. It never returns records.
func (s *PendingContentSource) FetchEvidence(context.Context, ContentRequest) ([]Record, error) {
	return nil, errors.Join(ErrUnavailable, ErrNoContentSource)
}
