package receipts

import "testing"

func TestResolveTargetPriorityOrdering(t *testing.T) {
	target, ok := ResolveTarget([]Target{
		{ID: "user_choice", Source: TargetSourceUserSelection, Channel: ChannelIM, Address: "im:user"},
		{ID: "policy_rule", Source: TargetSourcePolicyOrgRule, Channel: ChannelClaw, Address: "claw:manager"},
		{ID: "connector_config", Source: TargetSourceConnectorConfig, Channel: ChannelIM, Address: "im:owner"},
		{ID: "external_source", Source: TargetSourceExternalSource, Channel: ChannelClaw, Address: "claw:external"},
	})
	if !ok {
		t.Fatal("ResolveTarget returned ok=false")
	}
	if target.ID != "external_source" {
		t.Fatalf("target ID = %q, want external_source", target.ID)
	}
}

func TestCreateRequestAndDelivery(t *testing.T) {
	deliverer := &recordingDeliverer{}
	relay := NewRelay(deliverer)
	target := Target{ID: "target_1", Source: TargetSourceExternalSource, Channel: ChannelClaw, Address: "claw:manager"}

	req, err := relay.CreateAndDeliver(RequestInput{
		ID:           "receipt_req_1",
		EnterpriseID: "ent_1",
		CaseTicketID: "ticket_1",
		StepGrantID:  "grant_1",
		Target:       target,
	})
	if err != nil {
		t.Fatalf("CreateAndDeliver returned error: %v", err)
	}
	if req.Status != RequestStatusDelivered {
		t.Fatalf("status = %q, want delivered", req.Status)
	}
	if deliverer.last.ID != req.ID || deliverer.last.Target.ID != target.ID {
		t.Fatalf("delivered request = %+v, want request target", deliverer.last)
	}
}

type recordingDeliverer struct {
	last ReceiptRequest
}

func (d *recordingDeliverer) Deliver(request ReceiptRequest) error {
	d.last = request
	return nil
}
