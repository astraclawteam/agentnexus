package receipts

import "testing"

func TestVerifyReceiptAcceptsValidResults(t *testing.T) {
	request := ReceiptRequest{ID: "receipt_req_1", Status: RequestStatusPending}
	for _, result := range []ReceiptResult{ReceiptApproved, ReceiptDenied, ReceiptNarrowed, ReceiptInstructed} {
		receipt := Receipt{
			ID:        "receipt_1",
			RequestID: request.ID,
			Result:    result,
			Evidence:  "sha256:evidence",
		}
		if err := VerifyReceipt(request, receipt); err != nil {
			t.Fatalf("VerifyReceipt(%q) returned error: %v", result, err)
		}
	}
}

func TestInvalidReceiptIsRejected(t *testing.T) {
	request := ReceiptRequest{ID: "receipt_req_1", Status: RequestStatusPending}
	receipt := Receipt{
		ID:        "receipt_1",
		RequestID: "other_request",
		Result:    ReceiptResult("approved_by_business"),
	}

	if err := VerifyReceipt(request, receipt); err == nil {
		t.Fatal("VerifyReceipt returned nil, want invalid receipt error")
	}
}
