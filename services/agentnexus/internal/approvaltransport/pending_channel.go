package approvaltransport

import (
	"context"
	"errors"
)

// ErrNoDeliveryChannel is the transport failure reported by
// PendingDeliveryChannel. It is a deployment fact, not a bug: this deployment
// has no outbound integration with its approval authority.
var ErrNoDeliveryChannel = errors.New("approvaltransport: no outbound delivery channel is configured for this deployment")

// PendingDeliveryChannel accepts and durably correlates approval plans but
// never delivers them, because no outbound integration with a customer OA/BPM
// system exists yet (that is task B7: an endpoint, a credential, a payload
// contract with the external system, outbound TLS trust to a third-party host,
// and a retry policy -- none of which are built).
//
// It exists so the transmission surface can be REGISTERED and honest instead of
// absent. Without any channel the service cannot be constructed at all, so the
// four /v1/approvals/* routes are silently missing and AgentAtlas -- which was
// wired in stage 0 to transmit -- gets a bare 404 that says nothing about why.
//
// Deliver returns an error on purpose. Per the Channel contract that is a
// TRANSPORT failure: Service.transmit records a failed attempt with the coded
// reason "channel_unavailable" and leaves the transmission at StatusPending,
// which is precisely true -- the plan is correlated and durable, and nothing
// has reached an authority.
//
// Do NOT substitute MemoryChannel here. Its Deliver returns nil, which advances
// the transmission to StatusDelivered, and `delivered` on the frozen contract
// means "the plan reached the authority". That would be a lie on the wire to
// AgentAtlas, and a lie that reads as approval progress.
//
// The inbound half stays fully real: POST /v1/approvals/evidence does not
// depend on the channel having delivered, so an authority that receives a plan
// out of band can still record its signed decision and the refresh path will
// see it.
type PendingDeliveryChannel struct{}

// NewPendingDeliveryChannel builds the no-outbound-integration channel.
func NewPendingDeliveryChannel() *PendingDeliveryChannel { return &PendingDeliveryChannel{} }

func (c *PendingDeliveryChannel) Deliver(context.Context, Delivery) error {
	return ErrNoDeliveryChannel
}
