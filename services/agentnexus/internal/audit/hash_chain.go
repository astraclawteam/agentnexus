package audit

import (
	"fmt"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
)

// ComputeHash returns the sha256:<hex> event hash of an event, computed over the
// shared canonical pre-image (canonical.go). This is the hash-only layer: it
// links the tamper-evident chain and is independent of whether the event is
// signed (the canonical pre-image zeroes the signature slot).
func ComputeHash(event Event) string {
	hash, err := sdkaudit.EventHash(toSDK(event))
	if err != nil {
		// The pre-image is a fixed struct of strings, ints and times; json
		// marshaling never fails. An empty hash here would fail every downstream
		// verify, so surface the impossibility loudly rather than silently.
		panic(fmt.Sprintf("audit: canonical hash failed: %v", err))
	}
	return hash
}

// VerifyHashChain checks ONLY the hash-chain layer: each event's prev_hash links
// to the previous event's event_hash and its event_hash equals the recomputed
// canonical hash. It says nothing about signatures — the GA Task 0G signed
// verifier (Verify) adds signature, sequence and key-revocation checks on top.
func VerifyHashChain(events []Event) error {
	var prev string
	for _, event := range events {
		if event.PrevHash != prev {
			return fmt.Errorf("audit event %s prev_hash mismatch", event.ID)
		}
		if ComputeHash(event) != event.EventHash {
			return fmt.Errorf("audit event %s hash mismatch", event.ID)
		}
		prev = event.EventHash
	}
	return nil
}
