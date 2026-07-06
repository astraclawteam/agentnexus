package receipts

import "testing"

func TestRelayPersistsDeliveryAndCallbackLifecycle(t *testing.T) {
	store := NewMemoryStore()
	deliverer := &recordingDeliverer{}
	relay := NewRelayWithStore(store, deliverer)

	request, err := relay.CreateAndDeliver(RequestInput{
		ID:           "receipt_req_1",
		EnterpriseID: "ent_1",
		CaseTicketID: "ticket_1",
		StepGrantID:  "grant_1",
		Target:       Target{ID: "target_1", Source: TargetSourceExternalSource, Channel: ChannelClaw, Address: "claw:manager"},
	})
	if err != nil {
		t.Fatalf("CreateAndDeliver returned error: %v", err)
	}
	if request.Status != RequestStatusDelivered {
		t.Fatalf("request status = %q, want delivered", request.Status)
	}
	persisted, err := store.GetRequest("ent_1", request.ID)
	if err != nil {
		t.Fatalf("GetRequest returned error: %v", err)
	}
	if persisted.Status != RequestStatusDelivered {
		t.Fatalf("persisted status = %q, want delivered", persisted.Status)
	}

	receipt, err := relay.ReceiveCallback(CallbackInput{
		EnterpriseID: "ent_1",
		RequestID:    request.ID,
		ReceiptID:    "receipt_1",
		Result:       ReceiptApproved,
		Evidence:     "sha256:evidence",
	})
	if err != nil {
		t.Fatalf("ReceiveCallback returned error: %v", err)
	}
	if receipt.Result != ReceiptApproved {
		t.Fatalf("receipt = %+v", receipt)
	}
	approved, err := store.GetRequest("ent_1", request.ID)
	if err != nil {
		t.Fatalf("GetRequest after callback returned error: %v", err)
	}
	if approved.Status != RequestStatusApproved {
		t.Fatalf("approved status = %q, want approved", approved.Status)
	}
}
