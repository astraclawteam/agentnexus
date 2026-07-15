package audit

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// signer holds a registered key pair for building signed test chains.
type signer struct {
	keyID string
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
}

func newSigner(t *testing.T, keyID string) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return signer{keyID: keyID, pub: pub, priv: priv}
}

func (s signer) key(status KeyStatus) SigningKey {
	return SigningKey{KeyID: s.keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: s.pub, Status: status, CreatedAt: time.Unix(0, 0).UTC()}
}

var baseTime = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

// buildChain builds a valid signed chain of n events for one tenant: strict
// sequence 1..n, prev_hash linkage and a real ed25519 signature over each
// canonical pre-image.
func buildChain(t *testing.T, tenant string, s signer, n int) []Event {
	t.Helper()
	events := make([]Event, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		e := Event{
			ID:                  "audit_" + string(rune('a'+i)),
			TenantRef:           tenant,
			TenantSeq:           uint64(i + 1),
			ActorUserID:         "usr_principal",
			ResourceType:        "action",
			ResourceID:          "act_0000000000000001",
			Action:              "action.completed",
			Decision:            "succeeded",
			InputHash:           "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			StatusFrom:          "executing",
			Capability:          "erp.purchase_order.approve",
			ParameterHash:       "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			GrantRef:            "grant_0000000000000001",
			ApprovalEvidenceRef: "apv_0000000000000001",
			ReceiptRef:          "rcp_0000000000000001",
			RiskAuthority:       "acme-risk",
			AgentClientRef:      "agc_client-1",
			AgentReleaseRef:     "rel-1",
			OrgSnapshotRef:      "org-1",
			PrevHash:            prev,
			SignedAt:            baseTime.Add(time.Duration(i) * time.Second),
		}
		signed, err := SignEd25519(e, s.keyID, s.priv)
		if err != nil {
			t.Fatalf("sign event %d: %v", i, err)
		}
		events = append(events, signed)
		prev = signed.EventHash
	}
	return events
}

// rehash recomputes and stores event_hash after a field mutation, modelling a
// tamperer who fixes the (public) hash but cannot forge the signature.
func rehash(t *testing.T, e Event) Event {
	t.Helper()
	h, err := EventHash(e)
	if err != nil {
		t.Fatalf("rehash: %v", err)
	}
	e.EventHash = h
	return e
}

func TestVerifyChainAcceptsValidSignedChain(t *testing.T) {
	s := newSigner(t, "auditkey-1")
	chain := buildChain(t, "ent_1", s, 4)
	if err := VerifyChain(chain, NewKeySet(s.key(KeyActive))); err != nil {
		t.Fatalf("valid signed chain rejected: %v", err)
	}
}

func TestVerifyChainRejectsAttacks(t *testing.T) {
	s := newSigner(t, "auditkey-1")
	active := NewKeySet(s.key(KeyActive))

	cases := []struct {
		name    string
		mutate  func(t *testing.T, chain []Event, resolver KeyResolver) ([]Event, KeyResolver)
		wantErr error
	}{
		{
			name: "field mutation (decision) with rehash",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				last := len(chain) - 1
				chain[last].Decision = "failed"
				chain[last] = rehash(t, chain[last])
				return chain, r
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "naive field mutation without rehash",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				chain[len(chain)-1].Decision = "failed"
				return chain, r
			},
			wantErr: ErrHashMismatch,
		},
		{
			name: "forged timestamp",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				last := len(chain) - 1
				chain[last].SignedAt = chain[last].SignedAt.Add(-48 * time.Hour)
				chain[last] = rehash(t, chain[last])
				return chain, r
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "receipt substitution (receipt_ref column)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				last := len(chain) - 1
				chain[last].ReceiptRef = "rcp_9999999999999999"
				chain[last] = rehash(t, chain[last])
				return chain, r
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "detached approval/evidence binding (approval_evidence_ref column)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				last := len(chain) - 1
				chain[last].ApprovalEvidenceRef = "apv_9999999999999999"
				chain[last] = rehash(t, chain[last])
				return chain, r
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "operation binding substitution (capability column)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				last := len(chain) - 1
				chain[last].Capability = "erp.purchase_order.void"
				chain[last] = rehash(t, chain[last])
				return chain, r
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "chain linkage broken (prev_hash)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				last := len(chain) - 1
				chain[last].PrevHash = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"
				chain[last] = rehash(t, chain[last])
				return chain, r
			},
			wantErr: ErrChainBroken,
		},
		{
			name: "event deletion (sequence gap)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				return append(chain[:1], chain[2:]...), r
			},
			wantErr: ErrSequence,
		},
		{
			name: "reordering",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				chain[1], chain[2] = chain[2], chain[1]
				return chain, r
			},
			wantErr: ErrSequence,
		},
		{
			name: "duplicate sequence",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				chain[2].TenantSeq = chain[1].TenantSeq
				chain[2] = rehash(t, chain[2])
				return chain, r
			},
			wantErr: ErrSequence,
		},
		{
			name: "tenant splice",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				other := newSigner(t, "auditkey-2")
				foreign := buildChain(t, "ent_OTHER", other, 3)
				resolver := NewKeySet(s.key(KeyActive), other.key(KeyActive))
				chain[2] = foreign[2]
				return chain, resolver
			},
			wantErr: ErrTenantSplice,
		},
		{
			name: "unsigned event (legacy chain)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				chain[len(chain)-1].Signature = Signature{}
				return chain, r
			},
			wantErr: ErrUnsigned,
		},
		{
			name: "unknown signing key",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				return chain, NewKeySet() // empty resolver
			},
			wantErr: ErrUnknownKey,
		},
		{
			name: "revoked signing key",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				return chain, NewKeySet(s.key(KeyRevoked))
			},
			wantErr: ErrRevokedKey,
		},
		{
			name: "raw sensitive payload in hash slot (validly signed)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				e := chain[len(chain)-1]
				e.InputHash = "SSN=123-45-6789 raw account dump"
				signed, err := SignEd25519(e, s.keyID, s.priv)
				if err != nil {
					t.Fatalf("sign raw payload: %v", err)
				}
				chain[len(chain)-1] = signed
				return chain, r
			},
			wantErr: ErrRawPayload,
		},
		{
			name: "business outcome assertion (validly signed)",
			mutate: func(t *testing.T, chain []Event, r KeyResolver) ([]Event, KeyResolver) {
				e := chain[len(chain)-1]
				e.Decision = "goal_achieved"
				signed, err := SignEd25519(e, s.keyID, s.priv)
				if err != nil {
					t.Fatalf("sign outcome: %v", err)
				}
				chain[len(chain)-1] = signed
				return chain, r
			},
			wantErr: ErrOutcomeAssertion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := buildChain(t, "ent_1", s, 4)
			var resolver KeyResolver = active
			chain, resolver = tc.mutate(t, chain, resolver)
			err := VerifyChain(chain, resolver)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifyChain error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestMerkleRootAndProofRoundTrip(t *testing.T) {
	leaves := []string{"sha256:aa", "sha256:bb", "sha256:cc", "sha256:dd", "sha256:ee"}
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatalf("MerkleRoot: %v", err)
	}
	for i, leaf := range leaves {
		witness, err := MerkleProof(leaves, i)
		if err != nil {
			t.Fatalf("MerkleProof %d: %v", i, err)
		}
		if !VerifyMerkleProof(leaf, root, witness) {
			t.Fatalf("witness for leaf %d does not verify", i)
		}
		if VerifyMerkleProof("sha256:ff", root, witness) {
			t.Fatalf("witness verified a wrong leaf at %d", i)
		}
	}
}

func TestVerifyBundleRoundTripAndTamper(t *testing.T) {
	s := newSigner(t, "auditkey-1")
	chain := buildChain(t, "ent_1", s, 4)
	bundle, err := BuildBundle("ent_1", chain, []SigningKey{s.key(KeyActive)}, Ed25519Signer(s.keyID, s.priv))
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	raw, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	again, err := MarshalBundle(bundle)
	if err != nil || string(raw) != string(again) {
		t.Fatalf("MarshalBundle is not deterministic")
	}
	parsed, err := UnmarshalBundle(raw)
	if err != nil {
		t.Fatalf("UnmarshalBundle: %v", err)
	}
	trusted := NewKeySet(s.key(KeyActive))
	if err := VerifyBundle(parsed, trusted); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	// Tamper with an event inside the bundle: verification must fail.
	parsed.Events[2].Decision = "failed"
	parsed.Events[2] = rehash(t, parsed.Events[2])
	if err := VerifyBundle(parsed, trusted); err == nil {
		t.Fatalf("VerifyBundle accepted a tampered bundle")
	}
}

// TestVerifyBundleRejectsRogueKey is the authenticity guard: a bundle FULLY
// fabricated and self-signed by an attacker's own key (embedded as active in the
// bundle's own key list) must be REJECTED when verified against a legitimate
// trust anchor. Bundle self-consistency is not authenticity.
func TestVerifyBundleRejectsRogueKey(t *testing.T) {
	legit := newSigner(t, "legit-1")
	rogue := newSigner(t, "rogue-1")
	chain := buildChain(t, "ent_victim", rogue, 3)
	bundle, err := BuildBundle("ent_victim", chain, []SigningKey{rogue.key(KeyActive)}, Ed25519Signer(rogue.keyID, rogue.priv))
	if err != nil {
		t.Fatalf("build rogue bundle: %v", err)
	}
	// Self-signed rogue bundle is internally consistent...
	if err := VerifyBundle(bundle, NewKeySet(rogue.key(KeyActive))); err != nil {
		t.Fatalf("rogue bundle should be self-consistent: %v", err)
	}
	// ...but against the LEGITIMATE anchor it is rejected as untrusted.
	if err := VerifyBundle(bundle, NewKeySet(legit.key(KeyActive))); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("rogue-key bundle accepted against legit anchor: %v", err)
	}
	// A nil anchor is a hard error (never silent self-trust).
	if err := VerifyBundle(bundle, nil); err == nil {
		t.Fatalf("VerifyBundle accepted a bundle with no trust anchor")
	}
	// Substituting a rogue public key under a TRUSTED key id is rejected too.
	substituted := bundle
	substituted.Keys = []SigningKey{{KeyID: rogue.keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: legit.pub, Status: KeyActive}}
	if err := VerifyBundle(substituted, NewKeySet(legit.key(KeyActive))); err == nil {
		t.Fatalf("VerifyBundle accepted a key-substituted bundle")
	}
}
