package receipts

import "fmt"

func VerifyReceipt(request ReceiptRequest, receipt Receipt) error {
	if receipt.RequestID != request.ID {
		return fmt.Errorf("receipt request mismatch")
	}
	if !validReceiptResult(receipt.Result) {
		return fmt.Errorf("invalid receipt result %q", receipt.Result)
	}
	if receipt.Evidence == "" {
		return fmt.Errorf("receipt evidence is required")
	}
	return nil
}

func validReceiptResult(result ReceiptResult) bool {
	switch result {
	case ReceiptApproved, ReceiptDenied, ReceiptNarrowed, ReceiptInstructed:
		return true
	default:
		return false
	}
}
