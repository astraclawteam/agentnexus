package approvaltransport

import (
	"context"
	"sync"
	"time"
)

// Delivery is the outbound payload handed to the configured approval channel:
// the caller's signed plan reference and its exact operation binding,
// transmitted UNCHANGED. AgentNexus adds only the tenant scope and the
// attempt counter for correlation — it never rewrites, narrows or augments
// the plan, and there is deliberately no approver, queue or risk field to
// add.
type Delivery struct {
	TenantRef          string
	PlanRef            string
	PlanHash           string
	Authority          string
	BusinessContextRef string
	Capability         string
	ParameterHash      string
	Purpose            string
	ExpiresAt          time.Time
	Attempt            int
}

// Channel is the narrow outbound port to the external approval system
// (AgentAtlas, OA or BPM). A deployment configures exactly one channel;
// without a configured channel the transmission service cannot be
// constructed (fail closed — there is never a resolution fallback).
//
// Deliver returning an error is a TRANSPORT failure: the transmission stays
// pending, the attempt is recorded, and a later transmit of the same plan
// retries. Transport failure can never create approval progress.
type Channel interface {
	Deliver(ctx context.Context, delivery Delivery) error
}

// MemoryChannel is the real local Channel implementation used by unit tests,
// the e2e acceptance suite and local development: it records every accepted
// delivery in order and can simulate an outage.
type MemoryChannel struct {
	mu         sync.Mutex
	deliveries []Delivery
	fail       error
}

// NewMemoryChannel builds an empty in-process channel.
func NewMemoryChannel() *MemoryChannel { return &MemoryChannel{} }

// SetFailure makes every subsequent delivery fail with err (nil restores the
// channel).
func (c *MemoryChannel) SetFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = err
}

// Deliver records the delivery, or fails with the configured outage error.
func (c *MemoryChannel) Deliver(_ context.Context, delivery Delivery) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	c.deliveries = append(c.deliveries, delivery)
	return nil
}

// Deliveries returns a copy of the accepted deliveries in order.
func (c *MemoryChannel) Deliveries() []Delivery {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Delivery(nil), c.deliveries...)
}
