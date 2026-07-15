package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// canonicalTimePrecision is the frozen precision of every timestamp in the
// canonical pre-image: MICROSECONDS. Truncating here makes the signed bytes
// survive lossy boundaries losslessly - a PostgreSQL TIMESTAMPTZ column and an
// RFC 3339 JSON round-trip both preserve microseconds but not nanoseconds, so a
// sub-microsecond reading would make the persisted/exported event fail its own
// signature. Both the signer and every verifier normalize identically.
const canonicalTimePrecision = time.Microsecond

// Canonical returns the deterministic signing pre-image of an audit event: the
// encoding/json serialization of the event with BOTH mutable-integrity slots
// ZEROED (the signature and the event_hash) and the signed-at timestamp
// normalized to UTC.
//
// Canonicalization convention (mirrors the 0D CanonicalObservationReceipt
// convention): deterministic bytes come from encoding/json over the fixed Event
// struct - field order is the frozen json declaration order, no omitempty on any
// field, time.Time marshals as RFC 3339 UTC. A verifier rebuilds the exact
// pre-image from a transported event by zeroing the same two slots and
// re-marshaling. Both the event_hash and the signature are taken over THIS
// pre-image, so they bind identical content and any field mutation invalidates
// both.
func Canonical(e Event) ([]byte, error) {
	e.Signature = Signature{}
	e.EventHash = ""
	e.SignedAt = e.SignedAt.UTC().Truncate(canonicalTimePrecision)
	return json.Marshal(e)
}

// EventHash returns the sha256:<hex> hash of the canonical pre-image of e.
func EventHash(e Event) (string, error) {
	canonical, err := Canonical(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
