package approvaltransport

import (
	"context"
	"errors"
	"testing"
)

// The whole point of PendingDeliveryChannel is that it must never look like
// delivery succeeded. A nil return here would advance the transmission to
// StatusDelivered, and `delivered` on the frozen contract means the plan
// reached the authority -- a claim this deployment cannot make.
func TestPendingDeliveryChannelNeverClaimsDelivery(t *testing.T) {
	var channel Channel = NewPendingDeliveryChannel()
	err := channel.Deliver(context.Background(), Delivery{PlanRef: "apl_test", TenantRef: "ent-A"})
	if err == nil {
		t.Fatal("Deliver returned nil: the transmission would advance to delivered without reaching any authority")
	}
	if !errors.Is(err, ErrNoDeliveryChannel) {
		t.Errorf("Deliver error = %v, want ErrNoDeliveryChannel so the cause is identifiable", err)
	}
}
