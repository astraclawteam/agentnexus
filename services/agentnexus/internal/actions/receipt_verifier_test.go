package actions

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// signReceipt signs a receipt with a connector ed25519 key over the canonical
// receipt pre-image and returns the receipt carrying the signature.
func signReceipt(t *testing.T, receipt runtime.ActionReceipt, keyID string, key ed25519.PrivateKey) runtime.ActionReceipt {
	t.Helper()
	canonical, err := CanonicalActionReceipt(receipt)
	if err != nil {
		t.Fatalf("canonical receipt: %v", err)
	}
	receipt.Signature = &runtime.Signature{
		Algorithm: runtime.SignatureAlgorithmEd25519,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical)),
	}
	return receipt
}

func driveToExecuting(t *testing.T, svc *Service, principal runtime.PrincipalContext) Action {
	t.Helper()
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	executing, err := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	return executing
}

// TestReceiptCompletionFailsClosedWithoutVerifier proves the completion gate
// fails CLOSED: a service with NO receipt verifier wired must NOT complete an
// Action on a receipt, because without a verifier the signature cannot be
// checked ("only a verified signed ActionReceipt completes an Action"; the
// conformance requires_signature:true). This mirrors the audit path's hard
// ErrUnavailable rather than silently trusting an unverifiable receipt.
func TestReceiptCompletionFailsClosedWithoutVerifier(t *testing.T) {
	store := NewMemoryStore()
	svc, err := NewService(store, NewMemoryAuditSink(), WithIDGenerator(sequentialIDs()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()
	granted := mustGranted(t, svc, principal, testRequest(t))
	if _, err := svc.Dispatch(ctx, principal, granted.ActionRef); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	executing, err := svc.MarkExecuting(ctx, principal, granted.ActionRef)
	if err != nil {
		t.Fatalf("MarkExecuting: %v", err)
	}
	receipt := testReceipt(executing, runtime.StatusSucceeded) // structurally valid
	if _, err := svc.IngestReceipt(ctx, principal, "res-noverifier", receipt); !errors.Is(err, ErrReceiptRejected) {
		t.Fatalf("no-verifier completion err = %v, want ErrReceiptRejected (fail closed)", err)
	}
	after, err := svc.GetAction(ctx, principal, granted.ActionRef)
	if err != nil || after.Status != StatusExecuting {
		t.Fatalf("action after unverifiable receipt = %+v err=%v, want it to stay executing", after, err)
	}
}

// TestSignedReceiptCompletesActionOnlyWithVerifiedConnectorSignature proves the
// real SignedReceiptVerifier: a receipt signed by a registered connector key
// completes the Action, while a forged, unsigned, wrong-key or revoked-key
// receipt does not (0F left this seam nil).
func TestSignedReceiptCompletesActionOnlyWithVerifiedConnectorSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate connector key: %v", err)
	}
	keys := sdkaudit.NewKeySet(sdkaudit.SigningKey{
		KeyID: "connector-key-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyActive,
	})
	verifier := NewSignedReceiptVerifier(keys)
	principal := testPrincipal(runtime.TrustFirstParty)
	ctx := context.Background()

	t.Run("verified signed receipt completes the action", func(t *testing.T) {
		svc, _, _ := newTestService(t, WithReceiptVerifier(verifier))
		executing := driveToExecuting(t, svc, principal)
		receipt := signReceipt(t, testReceipt(executing, runtime.StatusSucceeded), "connector-key-1", priv)
		done, err := svc.IngestReceipt(ctx, principal, "res-signed", receipt)
		if err != nil {
			t.Fatalf("verified receipt rejected: %v", err)
		}
		if done.Status != StatusSucceeded {
			t.Fatalf("action status = %v, want succeeded", done.Status)
		}
	})

	t.Run("unsigned receipt does not complete the action", func(t *testing.T) {
		svc, _, _ := newTestService(t, WithReceiptVerifier(verifier))
		executing := driveToExecuting(t, svc, principal)
		receipt := testReceipt(executing, runtime.StatusSucceeded) // no signature
		if _, err := svc.IngestReceipt(ctx, principal, "res-unsigned", receipt); !errors.Is(err, ErrReceiptRejected) {
			t.Fatalf("unsigned receipt err = %v, want ErrReceiptRejected", err)
		}
	})

	t.Run("forged signature does not complete the action", func(t *testing.T) {
		svc, _, _ := newTestService(t, WithReceiptVerifier(verifier))
		executing := driveToExecuting(t, svc, principal)
		receipt := signReceipt(t, testReceipt(executing, runtime.StatusSucceeded), "connector-key-1", priv)
		// Tamper AFTER signing: the result no longer matches the signed bytes.
		forged := receipt
		forged.ResultHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
		forged.Result = nil
		if _, err := svc.IngestReceipt(ctx, principal, "res-forged", forged); !errors.Is(err, ErrReceiptRejected) {
			t.Fatalf("forged receipt err = %v, want ErrReceiptRejected", err)
		}
	})

	t.Run("wrong-key signature does not complete the action", func(t *testing.T) {
		svc, _, _ := newTestService(t, WithReceiptVerifier(verifier))
		executing := driveToExecuting(t, svc, principal)
		_, otherPriv, _ := ed25519.GenerateKey(nil)
		// Signed by a different key but CLAIMING the registered key id.
		receipt := signReceipt(t, testReceipt(executing, runtime.StatusSucceeded), "connector-key-1", otherPriv)
		if _, err := svc.IngestReceipt(ctx, principal, "res-wrongkey", receipt); !errors.Is(err, ErrReceiptRejected) {
			t.Fatalf("wrong-key receipt err = %v, want ErrReceiptRejected", err)
		}
	})

	t.Run("unknown key id does not complete the action", func(t *testing.T) {
		svc, _, _ := newTestService(t, WithReceiptVerifier(verifier))
		executing := driveToExecuting(t, svc, principal)
		receipt := signReceipt(t, testReceipt(executing, runtime.StatusSucceeded), "connector-key-UNKNOWN", priv)
		if _, err := svc.IngestReceipt(ctx, principal, "res-unknown", receipt); !errors.Is(err, ErrReceiptRejected) {
			t.Fatalf("unknown-key receipt err = %v, want ErrReceiptRejected", err)
		}
	})

	t.Run("revoked key does not complete the action", func(t *testing.T) {
		revoked := sdkaudit.NewKeySet(sdkaudit.SigningKey{
			KeyID: "connector-key-1", Algorithm: runtime.SignatureAlgorithmEd25519, PublicKey: pub, Status: sdkaudit.KeyRevoked,
		})
		svc, _, _ := newTestService(t, WithReceiptVerifier(NewSignedReceiptVerifier(revoked)))
		executing := driveToExecuting(t, svc, principal)
		receipt := signReceipt(t, testReceipt(executing, runtime.StatusSucceeded), "connector-key-1", priv)
		if _, err := svc.IngestReceipt(ctx, principal, "res-revoked", receipt); !errors.Is(err, ErrReceiptRejected) {
			t.Fatalf("revoked-key receipt err = %v, want ErrReceiptRejected", err)
		}
	})
}
