package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GA Task 0D amendment (plan revision dc81e80, deferral recorded in the
// task-0d handoff): verification-purpose reads bind the original Action and
// the declared PostconditionSpec/VerificationNeed pair server-side and mint a
// signed ObservationReceipt WITHOUT interpreting domain success.
//
// Fixture vocabulary. The topology canary is internal source topology that
// must never leak into a receipt, a log line or audit details; the record
// content deliberately uses domain-neutral state vocabulary (review_state)
// because the service must never branch on observed content.
const (
	verifyClass          = "erp.purchase_order_registry"
	verifyTopologyCanary = "erp-primary-CLASSIFIED-DSN-55/api/v3/purchase_orders"
	verifyActionRef      = "act_0123456789abcdef"
	verifyPostcondition  = "post-po-1001-applied"
	verifyNeed           = "verify-po-1001-applied"
	verifyFreshness      = 15 * time.Minute
)

func verifyParameterHash() string {
	return runtime.HashParameters([]byte(`{"po_number":"PO-1001"}`))
}

// testObservationSigner generates REAL ed25519 key material for one test.
// Observation signing is never faked: assertions verify the signature with
// the public key.
func testObservationSigner(t *testing.T) (*Ed25519ObservationSigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := NewEd25519ObservationSigner("obs-key-unit", priv)
	if err != nil {
		t.Fatalf("NewEd25519ObservationSigner: %v", err)
	}
	return signer, pub
}

type verificationFixture struct {
	*evidenceFixture
	pub ed25519.PublicKey
}

func newVerificationFixture(t *testing.T, opts ...Option) *verificationFixture {
	t.Helper()
	signer, pub := testObservationSigner(t)
	f := newFixture(t, append([]Option{WithObservationSigner(signer)}, opts...)...)
	return &verificationFixture{evidenceFixture: f, pub: pub}
}

// seedVerificationBinding registers the authority-declared registry row a
// verification read requires: a frozen authority tier plus a positive
// freshness bound, both internal-only (never part of the public contract).
func (f *evidenceFixture) seedVerificationBinding(t *testing.T, records []Record) SourceBinding {
	t.Helper()
	binding, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
		TenantRef:         testTenant,
		DataClass:         verifyClass,
		SourceRef:         verifyTopologyCanary,
		SourceVersion:     4,
		AccessCapability:  "knowledge.suggest",
		SourceCapability:  "",
		ResourceType:      "knowledge",
		ResourceID:        "erp-po-registry",
		CachedReadAllowed: true,
		AuthorityTier:     AuthorityTierSystemOfRecord,
		FreshnessBound:    verifyFreshness,
	})
	if err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	if records == nil {
		records = []Record{{"po_number": "PO-CONTENT-92k4", "review_state": "state-content-92k4"}}
	}
	f.source.Seed(binding.SourceRef, records)
	return binding
}

func verificationBlock() *runtime.VerificationBinding {
	return &runtime.VerificationBinding{
		ActionRef:          verifyActionRef,
		ParameterHash:      verifyParameterHash(),
		PostconditionID:    verifyPostcondition,
		VerificationNeedID: verifyNeed,
		DataClass:          verifyClass,
	}
}

// locateVerification stages the verification data class under the frozen
// verification purpose and returns the issued handle.
func (f *evidenceFixture) locateVerification(t *testing.T) (LocateResult, runtime.EvidenceHandle) {
	t.Helper()
	return f.locateOne(t, verifyClass, runtime.PurposeVerification)
}

// verificationRead builds the canonical verification-purpose read request.
func (f *evidenceFixture) verificationRead(businessContextRef, evidenceRef string) runtime.EvidenceReadRequest {
	req := f.readRequest(businessContextRef, evidenceRef, runtime.PurposeVerification, 0)
	req.VerificationBinding = verificationBlock()
	return req
}

func verifyReceiptSignature(t *testing.T, pub ed25519.PublicKey, receipt runtime.ObservationReceipt) {
	t.Helper()
	canonical, err := CanonicalObservationReceipt(receipt)
	if err != nil {
		t.Fatalf("CanonicalObservationReceipt: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(receipt.Signature.Value)
	if err != nil {
		t.Fatalf("signature value is not base64: %v", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("observation receipt signature must verify over the canonical receipt bytes")
	}
	// The signature binds the exact canonical bytes: any tamper breaks it.
	tampered := append([]byte(nil), canonical...)
	tampered[len(tampered)/2] ^= 0x01
	if ed25519.Verify(pub, tampered, sig) {
		t.Fatal("tampered canonical bytes must not verify")
	}
}

// --- Receipt minting ---------------------------------------------------------

func TestVerificationReadMintsSignedObservationReceipt(t *testing.T) {
	t.Parallel()
	f := newVerificationFixture(t)
	f.seedVerificationBinding(t, nil)
	stagedAt := *f.now

	located, handle := f.locateVerification(t)
	result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
		f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
	if err != nil {
		t.Fatalf("verification read: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Fatalf("decision = %q, want allow", result.Decision)
	}
	receipt := result.ObservationReceipt
	if receipt == nil {
		t.Fatal("a verification-purpose read must mint an observation receipt")
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("minted receipt must pass runtime.ObservationReceipt.Validate, got %v", err)
	}

	stored, err := f.store.GetHandle(context.Background(), testTenant, handle.EvidenceRef)
	if err != nil {
		t.Fatalf("GetHandle: %v", err)
	}
	if !strings.HasPrefix(receipt.ObservationRef, runtime.HandleObservation) {
		t.Errorf("observation_ref = %q, want opaque obs_ handle", receipt.ObservationRef)
	}
	if receipt.ActionRef != verifyActionRef || receipt.ParameterHash != verifyParameterHash() {
		t.Errorf("receipt must bind the original action exactly: %q %q", receipt.ActionRef, receipt.ParameterHash)
	}
	if receipt.PostconditionID != verifyPostcondition || receipt.VerificationNeedID != verifyNeed {
		t.Errorf("receipt must bind the declared postcondition/need pair: %q %q", receipt.PostconditionID, receipt.VerificationNeedID)
	}
	if receipt.Source != verifyClass {
		t.Errorf("receipt source = %q, want the business-semantic data class %q (never topology)", receipt.Source, verifyClass)
	}
	if receipt.SourceVersion != stored.SourceVersion {
		t.Errorf("receipt source_version = %d, want the sealed handle version %d", receipt.SourceVersion, stored.SourceVersion)
	}
	if receipt.Authority != AuthorityTierSystemOfRecord {
		t.Errorf("receipt authority = %q, want the registry-derived tier %q", receipt.Authority, AuthorityTierSystemOfRecord)
	}
	// Cache honesty: observed-at is the STAGING instant (when the source was
	// actually consulted), never the mint instant; freshness is the
	// registry-declared bound over it. A receipt never claims fresher than
	// the staged reality.
	if !receipt.ObservedAt.Equal(stagedAt) {
		t.Errorf("observed_at = %v, want the staging instant %v", receipt.ObservedAt, stagedAt)
	}
	if !receipt.FreshUntil.Equal(stagedAt.Add(verifyFreshness)) {
		t.Errorf("fresh_until = %v, want observed_at + declared bound %v", receipt.FreshUntil, stagedAt.Add(verifyFreshness))
	}
	if receipt.ObservationHash != "sha256:"+stored.ContentHash {
		t.Errorf("observation_hash = %q, want the staged normalized content digest sha256:%s", receipt.ObservationHash, stored.ContentHash)
	}
	if receipt.EvidenceRef != handle.EvidenceRef {
		t.Errorf("evidence_ref = %q, want the read handle %q", receipt.EvidenceRef, handle.EvidenceRef)
	}
	if receipt.Signature.Algorithm != runtime.SignatureAlgorithmEd25519 || receipt.Signature.KeyID != "obs-key-unit" {
		t.Errorf("signature identity = %+v, want ed25519/obs-key-unit", receipt.Signature)
	}
	verifyReceiptSignature(t, f.pub, *receipt)

	// audit_ref_id references the mandatory read-lineage append of THIS read,
	// and the lineage records the verification binding by refs/ids only.
	events := f.audit.Events()
	read := events[len(events)-1]
	if read.Action != auditActionRead {
		t.Fatalf("last lineage event = %q, want %q", read.Action, auditActionRead)
	}
	if receipt.AuditRefID == "" || !strings.HasPrefix(receipt.AuditRefID, "audit_") {
		t.Fatalf("audit_ref_id = %q, want the lineage reference of the read append", receipt.AuditRefID)
	}
	for key, want := range map[string]any{
		"action_ref":           verifyActionRef,
		"postcondition_id":     verifyPostcondition,
		"verification_need_id": verifyNeed,
		"observation_ref":      receipt.ObservationRef,
	} {
		if got := read.Details[key]; got != want {
			t.Errorf("read lineage %s = %v, want %v", key, got, want)
		}
	}

	// The receipt is refs, hashes, versions and bounds ONLY: no topology, no
	// observation content (the fixture record's keys and values are the
	// content canaries; the declared ids are deliberately disjoint from
	// them).
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{verifyTopologyCanary, "PO-CONTENT-92k4", "review_state", "state-content-92k4"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("receipt leaks %q: %s", banned, raw)
		}
	}

	// An ordinary read of another handle stays receipt-free: the response
	// shape of non-verification reads is unchanged.
	f.seedOpenBinding(t, nil)
	openLocated, openHandle := f.locateOne(t, openClass, testPurpose)
	ordinary, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
		f.readRequest(openLocated.BusinessContextRef, openHandle.EvidenceRef, testPurpose, 0))
	if err != nil {
		t.Fatalf("ordinary read: %v", err)
	}
	if ordinary.ObservationReceipt != nil {
		t.Fatal("an ordinary (non-verification) read must never mint an observation receipt")
	}
}

// TestVerificationReadMintsReceiptRegardlessOfObservedState proves the
// authority boundary in behavior: a "failed-looking" observation (the source
// reports a rejected review state) mints a receipt through exactly the same
// path as a "successful-looking" one. The receipt proves the observation, not
// an outcome; AgentNexus never inspects observed content for success
// semantics.
func TestVerificationReadMintsReceiptRegardlessOfObservedState(t *testing.T) {
	t.Parallel()
	f := newVerificationFixture(t)
	binding := f.seedVerificationBinding(t, []Record{{"po_number": "PO-1001", "review_state": "applied"}})

	located, handle := f.locateVerification(t)
	first, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
		f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
	if err != nil {
		t.Fatalf("first verification read: %v", err)
	}

	// The source moves on and now reports a rejected state; the prior handle
	// fails closed (stale) and a FRESH locate observes the new state.
	f.source.Seed(binding.SourceRef, []Record{{"po_number": "PO-1001", "review_state": "rejected", "review_note": "budget window closed"}})
	if _, err := f.svc.InvalidateSourceVersion(context.Background(), testTenant, verifyClass); err != nil {
		t.Fatalf("InvalidateSourceVersion: %v", err)
	}
	relocated, freshHandle := f.locateVerification(t)
	second, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
		f.verificationRead(relocated.BusinessContextRef, freshHandle.EvidenceRef))
	if err != nil {
		t.Fatalf("second verification read: %v", err)
	}

	for name, result := range map[string]ReadResult{"applied": first, "rejected": second} {
		if result.Decision != DecisionAllow || result.ObservationReceipt == nil {
			t.Fatalf("%s observation: decision=%q receipt=%v; the receipt proves the observation, never the outcome", name, result.Decision, result.ObservationReceipt)
		}
		if err := result.ObservationReceipt.Validate(); err != nil {
			t.Fatalf("%s observation receipt invalid: %v", name, err)
		}
	}
	a, b := first.ObservationReceipt, second.ObservationReceipt
	if a.ObservationHash == b.ObservationHash {
		t.Fatal("distinct observed content must produce distinct observation hashes")
	}
	if b.SourceVersion != a.SourceVersion+1 {
		t.Fatalf("second receipt source_version = %d, want %d (the moved-on source version)", b.SourceVersion, a.SourceVersion+1)
	}
	// Identical minting path: same action/postcondition/need binding, same
	// authority derivation, same signing identity - only observation-derived
	// facts differ.
	if a.ActionRef != b.ActionRef || a.PostconditionID != b.PostconditionID || a.VerificationNeedID != b.VerificationNeedID ||
		a.Authority != b.Authority || a.Source != b.Source || a.Signature.KeyID != b.Signature.KeyID {
		t.Fatal("the minting path must not depend on how the observed content looks")
	}
}

// --- Detached and mismatched verification needs ------------------------------

func TestVerificationReadRejectsDetachedNeed(t *testing.T) {
	t.Parallel()
	f := newVerificationFixture(t)
	f.seedVerificationBinding(t, nil)
	located, handle := f.locateVerification(t)

	t.Run("binding without the verification purpose", func(t *testing.T) {
		req := f.readRequest(located.BusinessContextRef, handle.EvidenceRef, testPurpose, 0)
		req.VerificationBinding = verificationBlock()
		_, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), req)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("detached binding (ordinary purpose) must be invalid, got %v", err)
		}
	})
	t.Run("verification purpose without a binding", func(t *testing.T) {
		req := f.readRequest(located.BusinessContextRef, handle.EvidenceRef, runtime.PurposeVerification, 0)
		_, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), req)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("detached verification purpose (no binding) must be invalid, got %v", err)
		}
	})
}

func TestVerificationReadRejectsMismatchedNeed(t *testing.T) {
	t.Parallel()
	f := newVerificationFixture(t)
	f.seedVerificationBinding(t, nil)
	located, handle := f.locateVerification(t)

	t.Run("declared data class conflicts with the resolved read", func(t *testing.T) {
		req := f.verificationRead(located.BusinessContextRef, handle.EvidenceRef)
		req.VerificationBinding.DataClass = openClass
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), req)
		if err != nil {
			t.Fatalf("mismatch must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny || result.ObservationReceipt != nil || result.Data != nil {
			t.Fatalf("mismatched need must fail closed without data or receipt: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyNeedMismatch)
	})
	t.Run("malformed parameter hash", func(t *testing.T) {
		req := f.verificationRead(located.BusinessContextRef, handle.EvidenceRef)
		req.VerificationBinding.ParameterHash = "sha256:zz"
		_, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), req)
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("malformed parameter hash must be invalid, got %v", err)
		}
	})
	t.Run("non-canonical identifiers", func(t *testing.T) {
		for name, mutate := range map[string]func(*runtime.VerificationBinding){
			"control bytes in postcondition id": func(b *runtime.VerificationBinding) { b.PostconditionID = "post\x00condition" },
			"oversized verification need id":    func(b *runtime.VerificationBinding) { b.VerificationNeedID = strings.Repeat("v", 200) },
			"padded data class":                 func(b *runtime.VerificationBinding) { b.DataClass = " " + verifyClass },
		} {
			t.Run(name, func(t *testing.T) {
				req := f.verificationRead(located.BusinessContextRef, handle.EvidenceRef)
				mutate(req.VerificationBinding)
				_, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), req)
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("non-canonical binding must be invalid, got %v", err)
				}
			})
		}
	})
	t.Run("verification read cannot hijack an ordinary handle", func(t *testing.T) {
		// The handle was located under an ordinary purpose; the verification
		// purpose therefore drifts from the handle binding and fails closed.
		f.seedOpenBinding(t, nil)
		openLocated, openHandle := f.locateOne(t, openClass, testPurpose)
		req := f.verificationRead(openLocated.BusinessContextRef, openHandle.EvidenceRef)
		req.VerificationBinding.DataClass = openClass
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), req)
		if err != nil {
			t.Fatalf("purpose drift must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny || result.ObservationReceipt != nil {
			t.Fatalf("purpose drift must fail closed without a receipt: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyPurposeDrift)
	})
}

func assertLastDenyReason(t *testing.T, f *evidenceFixture, want string) {
	t.Helper()
	events := f.audit.Events()
	if len(events) == 0 {
		t.Fatal("expected a lineage event")
	}
	last := events[len(events)-1]
	if last.Details["decision"] != DecisionDeny || last.Details["reason"] != want {
		t.Fatalf("last lineage event = %v, want deny reason %q", last.Details, want)
	}
}

// --- Forged or underivable observation authority/freshness -------------------

func TestVerificationReadRejectsForgedAuthorityAndFreshness(t *testing.T) {
	t.Parallel()

	t.Run("registry rejects malformed authority declarations", func(t *testing.T) {
		f := newVerificationFixture(t)
		base := SourceBinding{
			TenantRef: testTenant, DataClass: "erp.vendor_registry", SourceRef: "internal-vendor-store",
			AccessCapability: "knowledge.suggest", ResourceType: "knowledge", ResourceID: "vendors",
		}
		for name, mutate := range map[string]func(*SourceBinding){
			"unknown authority tier":         func(b *SourceBinding) { b.AuthorityTier = "self_asserted"; b.FreshnessBound = time.Minute },
			"tier without freshness bound":   func(b *SourceBinding) { b.AuthorityTier = AuthorityTierSystemOfRecord },
			"freshness bound without tier":   func(b *SourceBinding) { b.FreshnessBound = time.Minute },
			"negative freshness bound":       func(b *SourceBinding) { b.AuthorityTier = AuthorityTierDerived; b.FreshnessBound = -time.Second },
			"whitespace-padded tier literal": func(b *SourceBinding) { b.AuthorityTier = " system_of_record"; b.FreshnessBound = time.Minute },
		} {
			t.Run(name, func(t *testing.T) {
				binding := base
				mutate(&binding)
				if _, err := f.svc.RegisterSourceBinding(context.Background(), binding); !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("malformed authority declaration must be invalid, got %v", err)
				}
			})
		}
	})

	t.Run("undeclared authority fails closed", func(t *testing.T) {
		// The binding never declared an observation authority: there is no
		// server-side truth to derive, so the verification read is denied -
		// the service never invents a tier and never trusts the caller for
		// one.
		f := newVerificationFixture(t)
		binding, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
			TenantRef: testTenant, DataClass: verifyClass, SourceRef: verifyTopologyCanary,
			SourceVersion: 4, AccessCapability: "knowledge.suggest", ResourceType: "knowledge",
			ResourceID: "erp-po-registry", CachedReadAllowed: true,
		})
		if err != nil {
			t.Fatalf("RegisterSourceBinding: %v", err)
		}
		f.source.Seed(binding.SourceRef, []Record{{"po_number": "PO-1001"}})
		located, handle := f.locateVerification(t)
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil {
			t.Fatalf("undeclared authority must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny || result.ObservationReceipt != nil {
			t.Fatalf("undeclared authority must fail closed: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyObservationUnsupported)
	})

	t.Run("staleness beyond the freshness bound fails closed", func(t *testing.T) {
		// The staged observation aged past the declared freshness bound: the
		// receipt would have to claim fresher than reality, so the read is
		// denied. The server clock is the only clock.
		f := newVerificationFixture(t)
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		*f.now = f.now.Add(verifyFreshness + time.Second)
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil {
			t.Fatalf("stale observation must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny || result.ObservationReceipt != nil {
			t.Fatalf("stale observation must fail closed: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyObservationStale)
	})

	t.Run("durable registry no longer short-circuits an authority declaration", func(t *testing.T) {
		// Migration 000015 added authority_tier/freshness_bound_seconds, so
		// UpsertSourceBinding no longer refuses a declared binding outright.
		// The old refusal returned BEFORE touching the pool; the only way a
		// declaration can fail now is a real store failure, which against an
		// unreachable pool is a connection error.
		//
		// This is deliberately a narrow assertion. It proves the pre-store
		// rejection is gone, and nothing more - that the declaration actually
		// ROUND TRIPS is a claim only a real database can settle, and it is
		// settled by TestPostgresSourceBindingRoundTripsAuthorityDeclaration in
		// the DSN-gated integration suite. Asserting the round trip here with a
		// fake would prove only that the fake stores what it was handed.
		pool, err := pgxpool.New(context.Background(), "postgres://unit:unit@127.0.0.1:1/agentnexus_unreachable")
		if err != nil {
			t.Fatalf("lazy pool: %v", err)
		}
		t.Cleanup(pool.Close)
		store := NewPostgresStore(pool)
		_, err = store.UpsertSourceBinding(context.Background(), SourceBinding{
			TenantRef: testTenant, ID: "esb_unit", DataClass: verifyClass, SourceRef: "internal",
			SourceVersion: 1, AccessCapability: "knowledge.suggest", ResourceType: "knowledge",
			ResourceID: "erp-po-registry", AuthorityTier: AuthorityTierSystemOfRecord,
			FreshnessBound: verifyFreshness,
		})
		if err == nil {
			t.Fatal("an unreachable pool must still fail the upsert")
		}
		// The distinguishing fact: the failure is the DIAL, not a refusal to
		// persist the declaration. If the pre-store rejection came back, this
		// error would name the reserved migration slots and never reach the pool.
		if !strings.Contains(err.Error(), "dial") && !strings.Contains(err.Error(), "connect") {
			t.Fatalf("the declaration must reach the store and fail on connection, got %v", err)
		}
	})
}

// --- Unwired ports fail closed ------------------------------------------------

func TestVerificationReadFailsClosedWithoutSigner(t *testing.T) {
	t.Parallel()
	f := newFixture(t) // deliberately NO observation signer wired
	f.seedVerificationBinding(t, nil)
	located, handle := f.locateVerification(t)

	_, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
		f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("verification read without a wired signer must fail closed as unavailable, got %v", err)
	}

	// Ordinary reads are unaffected: the nil guard is verification-scoped.
	ordinary, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
		f.readRequest(located.BusinessContextRef, handle.EvidenceRef, runtime.PurposeVerification, 0))
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("detached verification purpose is invalid regardless of the signer, got %v %v", ordinary, err)
	}
	f.seedOpenBinding(t, nil)
	openLocated, openHandle := f.locateOne(t, openClass, testPurpose)
	result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
		f.readRequest(openLocated.BusinessContextRef, openHandle.EvidenceRef, testPurpose, 0))
	if err != nil || result.Decision != DecisionAllow {
		t.Fatalf("ordinary reads must keep working without an observation signer: %v %v", result, err)
	}
}

// TestVerificationReadActionBindingSeam pins the 0F seam: when an
// ActionBindingVerifier is wired it authoritatively checks the declared
// binding against the stored Action (Actions land in Task 0F); when it is
// nil the service performs the local self-consistency checks only - absence
// of the port never weakens them and never silently passes a wired
// rejection.
func TestVerificationReadActionBindingSeam(t *testing.T) {
	t.Parallel()

	t.Run("wired verifier rejection fails closed", func(t *testing.T) {
		verifier := &recordingActionBindingVerifier{err: errors.New("no such action")}
		f := newVerificationFixture(t, WithActionBindingVerifier(verifier))
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil {
			t.Fatalf("verifier rejection must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny || result.ObservationReceipt != nil {
			t.Fatalf("verifier rejection must fail closed: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyActionUnbound)
		if verifier.calls != 1 {
			t.Fatalf("verifier calls = %d, want 1", verifier.calls)
		}
	})

	t.Run("wired verifier sees the exact declared binding", func(t *testing.T) {
		verifier := &recordingActionBindingVerifier{}
		f := newVerificationFixture(t, WithActionBindingVerifier(verifier))
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil || result.Decision != DecisionAllow || result.ObservationReceipt == nil {
			t.Fatalf("wired accepting verifier must mint: %+v %v", result, err)
		}
		if verifier.tenantRef != testTenant || verifier.binding != *verificationBlock() {
			t.Fatalf("verifier saw %q %+v, want the exact declared binding", verifier.tenantRef, verifier.binding)
		}
	})

	t.Run("unwired seam keeps local checks and mints", func(t *testing.T) {
		f := newVerificationFixture(t)
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		mismatched := f.verificationRead(located.BusinessContextRef, handle.EvidenceRef)
		mismatched.VerificationBinding.DataClass = openClass
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(), mismatched)
		if err != nil || result.Decision != DecisionDeny {
			t.Fatalf("local mismatch checks must hold without the 0F port: %+v %v", result, err)
		}
		minted, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil || minted.ObservationReceipt == nil {
			t.Fatalf("consistent local binding must mint without the 0F port: %+v %v", minted, err)
		}
	})
}

type recordingActionBindingVerifier struct {
	calls     int
	tenantRef string
	binding   runtime.VerificationBinding
	err       error
}

func (r *recordingActionBindingVerifier) VerifyActionBinding(_ context.Context, tenantRef string, binding runtime.VerificationBinding) error {
	r.calls++
	r.tenantRef = tenantRef
	r.binding = binding
	return r.err
}

// --- Cache policy --------------------------------------------------------------

func TestVerificationReadHonorsCachePolicy(t *testing.T) {
	t.Parallel()

	t.Run("staged serving without the explicit cached-read grant fails closed", func(t *testing.T) {
		f := newVerificationFixture(t)
		binding, err := f.svc.RegisterSourceBinding(context.Background(), SourceBinding{
			TenantRef: testTenant, DataClass: verifyClass, SourceRef: verifyTopologyCanary,
			SourceVersion: 4, AccessCapability: "knowledge.suggest", ResourceType: "knowledge",
			ResourceID: "erp-po-registry", CachedReadAllowed: false,
			AuthorityTier: AuthorityTierSystemOfRecord, FreshnessBound: verifyFreshness,
		})
		if err != nil {
			t.Fatalf("RegisterSourceBinding: %v", err)
		}
		f.source.Seed(binding.SourceRef, []Record{{"po_number": "PO-1001"}})
		located, handle := f.locateVerification(t)
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil {
			t.Fatalf("cached-read denial must be typed, got error %v", err)
		}
		if result.Decision != DecisionDeny || result.ObservationReceipt != nil {
			t.Fatalf("verification reads serve staged content and therefore REQUIRE the explicit cached-read grant: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denyCachedRead)
	})

	t.Run("a moved-on source version never mints", func(t *testing.T) {
		f := newVerificationFixture(t)
		f.seedVerificationBinding(t, nil)
		located, handle := f.locateVerification(t)
		if _, err := f.svc.InvalidateSourceVersion(context.Background(), testTenant, verifyClass); err != nil {
			t.Fatalf("InvalidateSourceVersion: %v", err)
		}
		result, err := f.svc.Read(context.Background(), f.principal(testActor), fullAuthz(),
			f.verificationRead(located.BusinessContextRef, handle.EvidenceRef))
		if err != nil {
			t.Fatalf("stale version must be a typed deny, got error %v", err)
		}
		if result.Decision != DecisionDeny || result.ObservationReceipt != nil {
			t.Fatalf("a receipt must never attest a superseded source version: %+v", result)
		}
		assertLastDenyReason(t, f.evidenceFixture, denySourceVersionStale)
	})
}

// TestVerificationBindingValidationReportsDeterministicFirstError pins the
// ordered field-check idiom (fix round, code-review Minor 3): with SEVERAL
// non-canonical fields the reported first error is always the first field in
// the frozen contract declaration order - never a map-iteration lottery. 100
// iterations make a surviving randomized order practically impossible to
// miss (Go re-randomizes map ranges per iteration).
func TestVerificationBindingValidationReportsDeterministicFirstError(t *testing.T) {
	t.Parallel()
	broken := runtime.VerificationBinding{
		ActionRef:          verifyActionRef,
		ParameterHash:      verifyParameterHash(),
		PostconditionID:    "post\x00condition",
		VerificationNeedID: strings.Repeat("v", 200),
		DataClass:          " " + verifyClass,
	}
	const want = "postcondition_id is not canonical"
	for i := 0; i < 100; i++ {
		err := validateVerificationBinding(broken)
		if err == nil {
			t.Fatal("a binding with three non-canonical fields must be rejected")
		}
		if err.Error() != want {
			t.Fatalf("iteration %d: first error = %q, want deterministic %q (contract declaration order)", i, err.Error(), want)
		}
	}
}

// --- Signer construction guards -------------------------------------------------

func TestEd25519ObservationSignerRejectsBrokenKeyMaterial(t *testing.T) {
	t.Parallel()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEd25519ObservationSigner("", priv); err == nil {
		t.Fatal("a signer without a key id must be rejected")
	}
	if _, err := NewEd25519ObservationSigner("obs-key-unit", priv[:16]); err == nil {
		t.Fatal("truncated ed25519 key material must be rejected")
	}
	var nilSigner *Ed25519ObservationSigner
	if _, err := nilSigner.Sign(context.Background(), []byte("x")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil signer must fail closed, got %v", err)
	}
}
