package audit

import (
	"context"
	"errors"
	"fmt"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
)

// ErrTruncated marks a signed chain that has fewer events than a persisted
// batch-root checkpoint proved existed: the tail below the checkpoint's last
// sequence has been truncated (a deletion the live append-only ledger forbids,
// caught in an export/replica/dump by comparing against the signed checkpoint).
var ErrTruncated = errors.New("audit chain is truncated below a signed checkpoint")

// DetectTruncation reports truncation: a chain whose highest signed sequence
// (headSeq) is BELOW a persisted checkpoint's last covered sequence has lost
// evidence the checkpoint proved existed. A monotone or advancing head is fine.
func DetectTruncation(headSeq, checkpointLastSeq int64) error {
	if headSeq < checkpointLastSeq {
		return fmt.Errorf("%w: chain head seq %d is below checkpoint last seq %d", ErrTruncated, headSeq, checkpointLastSeq)
	}
	return nil
}

// VerificationPackage is the offline WORM/SIEM verification bundle: the ordered
// per-tenant events, the signing public keys with their revocation state, the
// signed batch Merkle root with its signer-asserted timestamp and per-event inclusion
// witnesses. Its bytes are deterministic and re-verifiable with stdlib crypto
// only (the standalone enterprise verifier consumes exactly this).
type VerificationPackage = sdkaudit.Bundle

// BuildVerificationPackage assembles and signs the offline verification package
// for a tenant's durable chain. The batch Merkle root is signed through the
// SAME AuditSigner port as the events (a KMS-backed key never leaves the port),
// and every signing public key referenced by the chain is bundled so an offline
// auditor needs no live service. The bytes returned by MarshalPackage are
// deterministic.
func BuildVerificationPackage(ctx context.Context, signer AuditSigner, tenant string, events []Event, keys []SigningKey) (VerificationPackage, error) {
	sdkEvents := make([]sdkaudit.Event, len(events))
	for i, e := range events {
		sdkEvents[i] = toSDK(e)
	}
	sign := func(canonical []byte) (sdkaudit.Signature, error) {
		signature, err := signer.Sign(ctx, canonical)
		if err != nil {
			return sdkaudit.Signature{}, err
		}
		return sdkaudit.Signature{Algorithm: signature.Algorithm, KeyID: signature.KeyID, Value: signature.Value}, nil
	}
	return sdkaudit.BuildBundle(tenant, sdkEvents, keys, sign)
}

// MarshalPackage serializes a verification package to deterministic bytes.
func MarshalPackage(pkg VerificationPackage) ([]byte, error) {
	return sdkaudit.MarshalBundle(pkg)
}

// VerifyPackage re-verifies an offline verification package end to end against a
// caller-supplied trust anchor (the pinned signing public keys). The anchor is
// REQUIRED; a package can never be its own trust root.
func VerifyPackage(pkg VerificationPackage, trusted KeyResolver) error {
	return sdkaudit.VerifyBundle(pkg, trusted)
}
