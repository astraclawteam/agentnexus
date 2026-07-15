package audit

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	stdruntime "runtime"
	"sort"
	"strings"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testSigner is an Ed25519AuditSigner plus its registered public key.
type testSigner struct {
	signer *Ed25519AuditSigner
	keyID  string
	pub    ed25519.PublicKey
}

func newTestSigner(t *testing.T, keyID string) testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewEd25519AuditSigner(keyID, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return testSigner{signer: signer, keyID: keyID, pub: pub}
}

func (s testSigner) keySet(status sdkaudit.KeyStatus) KeySet {
	return NewKeySet(SigningKey{KeyID: s.keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: s.pub, Status: status})
}

var chainBase = time.Date(2026, 7, 15, 9, 0, 0, 0, time.UTC)

// buildSignedChain builds a valid signed durable chain of n events for one
// tenant, through the SAME primitives the runtime append path uses
// (NewSignedEvent + SignEvent).
func buildSignedChain(t *testing.T, s testSigner, enterpriseID string, n int) []Event {
	t.Helper()
	events := make([]Event, 0, n)
	prev := ""
	for i := 0; i < n; i++ {
		input := EventInput{
			ID:                  fmt.Sprintf("audit_%02d", i+1),
			EnterpriseID:        enterpriseID,
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
		}
		event := NewSignedEvent(input, prev, uint64(i+1), chainBase.Add(time.Duration(i)*time.Second))
		signed, err := SignEvent(context.Background(), s.signer, nil, event)
		if err != nil {
			t.Fatalf("sign event %d: %v", i, err)
		}
		events = append(events, signed)
		prev = signed.EventHash
	}
	return events
}

func rehashEvent(t *testing.T, e Event) Event {
	t.Helper()
	e.EventHash = ComputeHash(e)
	return e
}

// TestVerifyDurableChain covers EVERY tamper dimension over the durable Event
// mapping (the sdk core is separately unit-tested); each maps to its sentinel.
func TestVerifyDurableChain(t *testing.T) {
	s := newTestSigner(t, "auditkey-core-1")
	active := s.keySet(sdkaudit.KeyActive)

	t.Run("valid signed chain verifies", func(t *testing.T) {
		if err := Verify(buildSignedChain(t, s, "ent_1", 4), active); err != nil {
			t.Fatalf("valid chain rejected: %v", err)
		}
	})

	cases := []struct {
		name    string
		mutate  func(t *testing.T, chain []Event) ([]Event, KeyResolver)
		wantErr error
	}{
		{"field mutation", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			c[3].Decision = "failed"
			c[3] = rehashEvent(t, c[3])
			return c, active
		}, ErrBadSignature},
		{"event deletion", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			return append(c[:1], c[2:]...), active
		}, ErrSequence},
		{"event insertion (duplicate seq)", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			c[2].TenantSeq = 2
			c[2] = rehashEvent(t, c[2])
			return c, active
		}, ErrSequence},
		{"reordering", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			c[1], c[2] = c[2], c[1]
			return c, active
		}, ErrSequence},
		{"tenant-chain splice", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			other := newTestSigner(t, "auditkey-core-2")
			foreign := buildSignedChain(t, other, "ent_OTHER", 4)
			c[2] = foreign[2]
			resolver := NewKeySet(
				SigningKey{KeyID: s.keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: s.pub, Status: sdkaudit.KeyActive},
				SigningKey{KeyID: other.keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: other.pub, Status: sdkaudit.KeyActive},
			)
			return c, resolver
		}, ErrTenantSplice},
		{"forged timestamp", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			c[3].SignedAt = c[3].SignedAt.Add(-72 * time.Hour)
			c[3] = rehashEvent(t, c[3])
			return c, active
		}, ErrBadSignature},
		{"revoked signing key", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			return c, s.keySet(sdkaudit.KeyRevoked)
		}, ErrRevokedKey},
		{"raw sensitive payload", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			input := EventInput{ID: c[3].ID, EnterpriseID: c[3].EnterpriseID, ResourceType: "action", ResourceID: c[3].ResourceID, Action: c[3].Action, Decision: c[3].Decision, InputHash: "SSN=123-45-6789"}
			e := NewSignedEvent(input, c[3].PrevHash, c[3].TenantSeq, c[3].SignedAt)
			signed, err := SignEvent(context.Background(), s.signer, nil, e)
			if err != nil {
				t.Fatalf("sign raw: %v", err)
			}
			c[3] = signed
			return c, active
		}, ErrRawPayload},
		{"receipt substitution (receipt_ref column)", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			c[3].ReceiptRef = "rcp_9999999999999999"
			c[3] = rehashEvent(t, c[3])
			return c, active
		}, ErrBadSignature},
		{"detached approval-evidence binding (approval_evidence_ref column)", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			c[3].ApprovalEvidenceRef = "apv_9999999999999999"
			c[3] = rehashEvent(t, c[3])
			return c, active
		}, ErrBadSignature},
		{"operation substitution (capability column)", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			c[3].Capability = "erp.purchase_order.void"
			c[3] = rehashEvent(t, c[3])
			return c, active
		}, ErrBadSignature},
		{"business outcome assertion", func(t *testing.T, c []Event) ([]Event, KeyResolver) {
			input := EventInput{ID: c[3].ID, EnterpriseID: c[3].EnterpriseID, ResourceType: "action", ResourceID: c[3].ResourceID, Action: c[3].Action, Decision: "goal_achieved", InputHash: c[3].InputHash}
			e := NewSignedEvent(input, c[3].PrevHash, c[3].TenantSeq, c[3].SignedAt)
			signed, err := SignEvent(context.Background(), s.signer, nil, e)
			if err != nil {
				t.Fatalf("sign outcome: %v", err)
			}
			c[3] = signed
			return c, active
		}, ErrOutcomeAssertion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain, resolver := tc.mutate(t, buildSignedChain(t, s, "ent_1", 4))
			if err := Verify(chain, resolver); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestVerifyRejectsExistingUnsignedChain proves the legacy UNSIGNED SHA-256
// chain (NewEvent, no signature) fails the signed verifier.
func TestVerifyRejectsExistingUnsignedChain(t *testing.T) {
	prev := ""
	var events []Event
	for i := 0; i < 3; i++ {
		e := NewEvent(EventInput{ID: fmt.Sprintf("legacy_%d", i), EnterpriseID: "ent_1", Action: "read", Decision: "allow"}, prev)
		events = append(events, e)
		prev = e.EventHash
	}
	// The legacy chain still passes the hash-only layer...
	if err := VerifyHashChain(events); err != nil {
		t.Fatalf("legacy chain fails the hash-only layer: %v", err)
	}
	// ...but the signed verifier rejects it (unsigned authority).
	if err := Verify(events, NewKeySet()); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("signed verifier accepted an unsigned chain: %v", err)
	}
}

// ---- Real-Postgres persistence / sequence / duplicate / DB-rewrite ----

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN to run the audit postgres integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	schema := fmt.Sprintf("agentnexus_audit_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("parse dsn: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatalf("connect schema pool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, _ = admin.Exec(cleanupCtx, `DROP SCHEMA IF EXISTS `+pgx.Identifier{schema}.Sanitize()+` CASCADE`)
		admin.Close()
	})
	applyAllMigrations(t, pool)
	return pool
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := stdruntime.Caller(0)
	if !ok {
		t.Fatal("cannot locate migrations directory")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations"))
}

func gooseBlock(t *testing.T, name, direction string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(migrationsDir(t), name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	text := string(raw)
	marker := "-- +goose " + direction
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("migration %s is missing %q", name, marker)
	}
	segment := text[start:]
	if direction == "Up" {
		if down := strings.Index(segment, "-- +goose Down"); down >= 0 {
			segment = segment[:down]
		}
	}
	segment = strings.ReplaceAll(segment, "-- +goose StatementBegin", "")
	segment = strings.ReplaceAll(segment, "-- +goose StatementEnd", "")
	return strings.TrimPrefix(segment, marker)
}

func applyAllMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, name := range names {
		if _, err := pool.Exec(ctx, gooseBlock(t, name, "Up")); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
}

func text(v string) pgtype.Text {
	if v == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: v, Valid: true}
}

// appendSignedToDB persists one signed event under the per-enterprise advisory
// lock, allocating the next tenant sequence (mirrors the runtime signing
// writer). It returns the persisted event.
func appendSignedToDB(t *testing.T, ctx context.Context, pool *pgxpool.Pool, s testSigner, enterpriseID string, input EventInput) Event {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := db.New(tx)
	if _, err := q.AcquireEnterpriseAuditLock(ctx, enterpriseID); err != nil {
		t.Fatalf("lock: %v", err)
	}
	prev, err := q.GetLatestEnterpriseAuditHash(ctx, enterpriseID)
	if err != nil {
		t.Fatalf("prev hash: %v", err)
	}
	seq, err := q.AllocateNextTenantSeq(ctx, enterpriseID)
	if err != nil {
		t.Fatalf("allocate seq: %v", err)
	}
	input.EnterpriseID = enterpriseID
	event := NewSignedEvent(input, prev, uint64(seq), time.Now())
	signed, err := SignEvent(ctx, s.signer, nil, event)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := q.AppendSignedAuditEvent(ctx, db.AppendSignedAuditEventParams{
		ID: signed.ID, EnterpriseID: enterpriseID, ActorUserID: text(signed.ActorUserID),
		ResourceType: text(signed.ResourceType), ResourceID: text(signed.ResourceID),
		Action: signed.Action, Decision: signed.Decision, InputHash: text(signed.InputHash),
		EvidencePointer: text(signed.EvidencePointer), PrevHash: text(signed.PrevHash),
		EventHash: signed.EventHash, TenantSeq: pgtype.Int8{Int64: seq, Valid: true},
		SignatureAlgorithm: text(signed.Signature.Algorithm), SignatureKeyID: text(signed.Signature.KeyID),
		SignatureValue: text(signed.Signature.Value), SignedAt: pgtype.Timestamptz{Time: signed.SignedAt, Valid: true},
		StatusFrom: text(signed.StatusFrom), Capability: text(signed.Capability), ParameterHash: text(signed.ParameterHash),
		GrantRef: text(signed.GrantRef), ApprovalEvidenceRef: text(signed.ApprovalEvidenceRef), ReceiptRef: text(signed.ReceiptRef),
		RiskAuthority: text(signed.RiskAuthority), AgentClientRef: text(signed.AgentClientRef),
		AgentReleaseRef: text(signed.AgentReleaseRef), OrgSnapshotRef: text(signed.OrgSnapshotRef),
	}); err != nil {
		t.Fatalf("append signed: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return signed
}

func fromDB(row db.AuditEvent) Event {
	e := Event{
		ID: row.ID, EnterpriseID: row.EnterpriseID, CaseTicketID: row.CaseTicketID.String,
		StepGrantID: row.StepGrantID.String, ActorUserID: row.ActorUserID.String,
		ConnectorInstanceID: row.ConnectorInstanceID.String, ResourceType: row.ResourceType.String,
		ResourceID: row.ResourceID.String, Action: row.Action, Decision: row.Decision,
		InputHash: row.InputHash.String, OutputHash: row.OutputHash.String,
		EvidencePointer: row.EvidencePointer.String, PrevHash: row.PrevHash.String, EventHash: row.EventHash,
		StatusFrom: row.StatusFrom.String, Capability: row.Capability.String, ParameterHash: row.ParameterHash.String,
		GrantRef: row.GrantRef.String, ApprovalEvidenceRef: row.ApprovalEvidenceRef.String, ReceiptRef: row.ReceiptRef.String,
		RiskAuthority: row.RiskAuthority.String, AgentClientRef: row.AgentClientRef.String,
		AgentReleaseRef: row.AgentReleaseRef.String, OrgSnapshotRef: row.OrgSnapshotRef.String,
	}
	if row.TenantSeq.Valid {
		e.TenantSeq = uint64(row.TenantSeq.Int64)
	}
	if row.SignedAt.Valid {
		e.SignedAt = row.SignedAt.Time
	}
	if row.SignatureKeyID.Valid {
		e.Signature = runtime.Signature{Algorithm: row.SignatureAlgorithm.String, KeyID: row.SignatureKeyID.String, Value: row.SignatureValue.String}
	}
	return e
}

func readChain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, enterpriseID string) []Event {
	t.Helper()
	rows, err := db.New(pool).ListSignedAuditEventsForTenant(ctx, enterpriseID)
	if err != nil {
		t.Fatalf("list signed: %v", err)
	}
	events := make([]Event, len(rows))
	for i, row := range rows {
		events[i] = fromDB(row)
	}
	return events
}

func TestSignedAuditChainPersistsAndVerifies(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	enterpriseID := "ent_persist"
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1, $2)`, enterpriseID, "Persist Co"); err != nil {
		t.Fatalf("seed enterprise: %v", err)
	}
	s := newTestSigner(t, "auditkey-db-1")
	if _, err := db.New(pool).UpsertAuditSigningKey(ctx, db.UpsertAuditSigningKeyParams{KeyID: s.keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: s.pub}); err != nil {
		t.Fatalf("register key: %v", err)
	}

	for i := 0; i < 3; i++ {
		appendSignedToDB(t, ctx, pool, s, enterpriseID, EventInput{ID: fmt.Sprintf("audit_db_%d", i), ActorUserID: "usr_1", ResourceType: "action", ResourceID: "act_0000000000000001", Action: "action.completed", Decision: "succeeded", InputHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222"})
	}

	t.Run("round-trip verifies against registered key", func(t *testing.T) {
		if err := Verify(readChain(t, ctx, pool, enterpriseID), s.keySet(sdkaudit.KeyActive)); err != nil {
			t.Fatalf("persisted chain rejected: %v", err)
		}
	})

	t.Run("next sequence is monotonic", func(t *testing.T) {
		next, err := db.New(pool).AllocateNextTenantSeq(ctx, enterpriseID)
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		if next != 4 {
			t.Fatalf("next seq = %d, want 4", next)
		}
	})

	t.Run("live audit_events table rejects in-place rewrite", func(t *testing.T) {
		// Defense in depth: the live ledger is append-only at the database
		// (guard_audit_ledger_append_only, migration 000005), so a DB admin
		// cannot rewrite a row in place at all.
		_, err := pool.Exec(ctx, `UPDATE audit_events SET decision = 'failed' WHERE enterprise_id = $1 AND tenant_seq = 2`, enterpriseID)
		if err == nil {
			t.Fatalf("live audit_events accepted an in-place UPDATE; the append-only guard is missing")
		}
	})

	t.Run("tampered export/dump is detected by the signature", func(t *testing.T) {
		// A tamperer who cannot rewrite the live append-only table instead edits
		// an exported dump or a replica. The signed chain catches it offline: a
		// mutated decision (with a naively recomputed event_hash) fails the
		// ed25519 signature over the canonical pre-image.
		dumped := readChain(t, ctx, pool, enterpriseID)
		dumped[1].Decision = "failed"
		dumped[1] = rehashEvent(t, dumped[1])
		if err := Verify(dumped, s.keySet(sdkaudit.KeyActive)); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("tampered dump not caught: %v", err)
		}
		// A revoked signing key invalidates the whole exported chain.
		if err := Verify(readChain(t, ctx, pool, enterpriseID), s.keySet(sdkaudit.KeyRevoked)); !errors.Is(err, ErrRevokedKey) {
			t.Fatalf("revoked-key export not rejected: %v", err)
		}
	})
}

func TestSignedAuditDuplicateSequenceRejectedByDatabase(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	enterpriseID := "ent_dup"
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1, $2)`, enterpriseID, "Dup Co"); err != nil {
		t.Fatalf("seed enterprise: %v", err)
	}
	// First row at tenant_seq = 1.
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_events (id, enterprise_id, action, decision, event_hash, tenant_seq, signature_algorithm, signature_key_id, signature_value, signed_at)
		 VALUES ($1,$2,'a','succeeded','sha256:aa',1,'ed25519','k','v',now())`,
		"dup_1", enterpriseID); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	// Second row reusing tenant_seq = 1 must violate the partial unique index.
	_, err := pool.Exec(ctx,
		`INSERT INTO audit_events (id, enterprise_id, action, decision, event_hash, tenant_seq, signature_algorithm, signature_key_id, signature_value, signed_at)
		 VALUES ($1,$2,'b','succeeded','sha256:bb',1,'ed25519','k','v',now())`,
		"dup_2", enterpriseID)
	if err == nil {
		t.Fatalf("database accepted a duplicate (enterprise_id, tenant_seq)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") && !strings.Contains(err.Error(), "audit_events_tenant_seq_uniq") {
		t.Fatalf("duplicate-sequence rejection was not a unique violation: %v", err)
	}
}

func TestVerificationPackageRoundTrip(t *testing.T) {
	s := newTestSigner(t, "auditkey-pkg-1")
	chain := buildSignedChain(t, s, "ent_pkg", 4)
	keys := []SigningKey{{KeyID: s.keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: s.pub, Status: sdkaudit.KeyActive}}
	pkg, err := BuildVerificationPackage(context.Background(), s.signer, "ent_pkg", chain, keys)
	if err != nil {
		t.Fatalf("build package: %v", err)
	}
	raw, err := MarshalPackage(pkg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := sdkaudit.UnmarshalBundle(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	trusted := s.keySet(sdkaudit.KeyActive)
	if err := VerifyPackage(parsed, trusted); err != nil {
		t.Fatalf("valid package rejected: %v", err)
	}
	// Authenticity: a foreign anchor rejects an otherwise-valid package.
	other := newTestSigner(t, "auditkey-pkg-rogue")
	if err := VerifyPackage(parsed, other.keySet(sdkaudit.KeyActive)); err == nil {
		t.Fatalf("package verified against a foreign anchor")
	}
}

func TestDetectTruncation(t *testing.T) {
	if err := DetectTruncation(5, 5); err != nil {
		t.Fatalf("intact chain (head==checkpoint) reported truncated: %v", err)
	}
	if err := DetectTruncation(6, 5); err != nil {
		t.Fatalf("advanced chain reported truncated: %v", err)
	}
	if err := DetectTruncation(3, 5); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated chain (head<checkpoint) not detected: %v", err)
	}
}
