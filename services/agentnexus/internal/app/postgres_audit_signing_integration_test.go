package app

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
	"sync"
	"testing"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This suite gives the REAL production sink method (PostgresBrowserAuditSink.
// AppendActionTransitionAudit) behavioral coverage against REAL PostgreSQL, so
// the conformance integrity_failure claims are demonstrated, not merely asserted
// as YAML literals.

func auditSigningPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN to run the audit-signing sink integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	schema := fmt.Sprintf("agentnexus_auditsign_%d", time.Now().UnixNano())
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
	applyAuditSigningMigrations(t, pool)
	return pool
}

func applyAuditSigningMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, file, _, ok := stdruntime.Caller(0)
	if !ok {
		t.Fatal("cannot locate migrations directory")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "db", "migrations"))
	entries, err := os.ReadDir(dir)
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
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(raw)
		start := strings.Index(text, "-- +goose Up")
		if start < 0 {
			t.Fatalf("%s missing +goose Up", name)
		}
		seg := text[start:]
		if down := strings.Index(seg, "-- +goose Down"); down >= 0 {
			seg = seg[:down]
		}
		seg = strings.ReplaceAll(seg, "-- +goose StatementBegin", "")
		seg = strings.ReplaceAll(seg, "-- +goose StatementEnd", "")
		if _, err := pool.Exec(ctx, strings.TrimPrefix(seg, "-- +goose Up")); err != nil {
			t.Fatalf("migration %s: %v", name, err)
		}
	}
}

func newAuditSigner(t *testing.T, keyID string) (*audit.Ed25519AuditSigner, sdkaudit.KeySet) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := audit.NewEd25519AuditSigner(keyID, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, audit.NewKeySet(audit.SigningKey{KeyID: signer.KeyID(), Algorithm: audit.SignatureAlgorithmEd25519, PublicKey: signer.PublicKey(), Status: sdkaudit.KeyActive})
}

func actionAuditEvent(tenant, actionRef string, from, to runtime.ActionStatus) actions.AuditEvent {
	return actions.AuditEvent{
		TenantRef: tenant, PrincipalRef: "usr_principal", Action: "action.completed",
		ActionRef: actionRef, StatusFrom: from, StatusTo: to,
		Capability: "erp.purchase_order.approve", ParameterHash: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		GrantRef: "grant_0000000000000001", ApprovalEvidenceRef: "apv_0000000000000001", ReceiptRef: "rcp_0000000000000001",
		RiskAuthority: "acme-risk", AgentClientRef: "agc_client-1", AgentReleaseRef: "rel-1", OrgSnapshotRef: "org-1",
		Details: map[string]any{"result_id": "res-1"},
	}
}

// failingSigner injects a signing outage.
type failingSigner struct{}

func (failingSigner) Sign(context.Context, []byte) (runtime.Signature, error) {
	return runtime.Signature{}, errors.New("kms unavailable")
}

func readSignedChain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant string) []audit.Event {
	t.Helper()
	rows, err := db.New(pool).ListSignedAuditEventsForTenant(ctx, tenant)
	if err != nil {
		t.Fatalf("list signed: %v", err)
	}
	out := make([]audit.Event, len(rows))
	for i, r := range rows {
		e := audit.Event{
			ID: r.ID, EnterpriseID: r.EnterpriseID, ActorUserID: r.ActorUserID.String,
			ResourceType: r.ResourceType.String, ResourceID: r.ResourceID.String, Action: r.Action, Decision: r.Decision,
			InputHash: r.InputHash.String, EvidencePointer: r.EvidencePointer.String, PrevHash: r.PrevHash.String, EventHash: r.EventHash,
			StatusFrom: r.StatusFrom.String, Capability: r.Capability.String, ParameterHash: r.ParameterHash.String,
			GrantRef: r.GrantRef.String, ApprovalEvidenceRef: r.ApprovalEvidenceRef.String, ReceiptRef: r.ReceiptRef.String,
			RiskAuthority: r.RiskAuthority.String, AgentClientRef: r.AgentClientRef.String, AgentReleaseRef: r.AgentReleaseRef.String,
			OrgSnapshotRef: r.OrgSnapshotRef.String,
		}
		if r.TenantSeq.Valid {
			e.TenantSeq = uint64(r.TenantSeq.Int64)
		}
		if r.SignedAt.Valid {
			e.SignedAt = r.SignedAt.Time
		}
		if r.SignatureKeyID.Valid {
			e.Signature = runtime.Signature{Algorithm: r.SignatureAlgorithm.String, KeyID: r.SignatureKeyID.String, Value: r.SignatureValue.String}
		}
		out[i] = e
	}
	return out
}

func TestActionTransitionAuditSinkFailsClosedAndVerifies(t *testing.T) {
	pool := auditSigningPool(t)
	ctx := context.Background()
	tenant := "ent_sink"
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1,$2)`, tenant, "Sink Co"); err != nil {
		t.Fatalf("seed enterprise: %v", err)
	}
	signer, keys := newAuditSigner(t, "audit-sink-1")

	t.Run("nil signer blocks the high-risk transition (fail closed)", func(t *testing.T) {
		sink := NewPostgresBrowserAuditSink(pool) // NO signer
		_, err := sink.AppendActionTransitionAudit(ctx, actionAuditEvent(tenant, "act_0000000000000001", "executing", "succeeded"))
		if !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("nil-signer append err = %v, want audit.ErrUnavailable (fail closed)", err)
		}
		// Nothing was persisted: no unsigned high-risk audit record leaks through.
		if got := readSignedChain(t, ctx, pool, tenant); len(got) != 0 {
			t.Fatalf("nil-signer append persisted %d rows, want 0", len(got))
		}
	})

	t.Run("wired signer appends a signed, sequenced chain that verifies", func(t *testing.T) {
		sink := NewPostgresBrowserAuditSink(pool, WithAuditSigner(signer))
		for i := 0; i < 3; i++ {
			if _, err := sink.AppendActionTransitionAudit(ctx, actionAuditEvent(tenant, fmt.Sprintf("act_000000000000000%d", i+1), "executing", "succeeded")); err != nil {
				t.Fatalf("append %d: %v", i, err)
			}
		}
		chain := readSignedChain(t, ctx, pool, tenant)
		if len(chain) != 3 {
			t.Fatalf("chain len = %d, want 3", len(chain))
		}
		for i, e := range chain {
			if e.TenantSeq != uint64(i+1) {
				t.Fatalf("event %d tenant_seq = %d, want %d", i, e.TenantSeq, i+1)
			}
			if e.Capability == "" || e.ReceiptRef == "" {
				t.Fatalf("event %d lost its first-class binding refs: %+v", i, e)
			}
		}
		if err := audit.Verify(chain, keys); err != nil {
			t.Fatalf("persisted signed chain does not verify: %v", err)
		}
	})

	t.Run("during a signing outage, diagnostics and export still function", func(t *testing.T) {
		// The append path fails closed on a signer outage...
		outageSink := NewPostgresBrowserAuditSink(pool, WithAuditSigner(failingSigner{}))
		if _, err := outageSink.AppendActionTransitionAudit(ctx, actionAuditEvent(tenant, "act_0000000000000009", "executing", "succeeded")); err == nil {
			t.Fatal("append during signer outage unexpectedly succeeded")
		}
		// ...but the already-committed chain remains readable and verifiable with
		// only the registered public keys (no signer needed): preserves_diagnostics.
		chain := readSignedChain(t, ctx, pool, tenant)
		if len(chain) != 3 {
			t.Fatalf("outage must not truncate the committed chain: len=%d", len(chain))
		}
		if err := audit.Verify(chain, keys); err != nil {
			t.Fatalf("committed chain fails to verify during outage: %v", err)
		}
		// And it exports into a verifiable offline package: preserves_export.
		pkg, err := audit.BuildVerificationPackage(ctx, signer, tenant, chain, keysList(keys))
		if err != nil {
			t.Fatalf("export during outage: %v", err)
		}
		if err := audit.VerifyPackage(pkg, keys); err != nil {
			t.Fatalf("exported package does not verify: %v", err)
		}
	})
}

// TestSignedAuditCheckpointDetectsTruncation proves the batch-root checkpoint
// surface: a signed checkpoint is persisted, export produces a verifiable
// bundle, and a chain shorter than a persisted checkpoint (a truncated
// restore/replica) is DETECTED. Without this, truncation below the last
// checkpoint would be invisible.
func TestSignedAuditCheckpointDetectsTruncation(t *testing.T) {
	pool := auditSigningPool(t)
	ctx := context.Background()
	tenant := "ent_trunc"
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1,$2)`, tenant, "Trunc Co"); err != nil {
		t.Fatalf("seed enterprise: %v", err)
	}
	signer, keys := newAuditSigner(t, "audit-trunc-1")
	if _, err := db.New(pool).UpsertAuditSigningKey(ctx, db.UpsertAuditSigningKeyParams{KeyID: signer.KeyID(), Algorithm: audit.SignatureAlgorithmEd25519, PublicKey: signer.PublicKey()}); err != nil {
		t.Fatalf("register key: %v", err)
	}
	sink := NewPostgresBrowserAuditSink(pool, WithAuditSigner(signer))
	for i := 0; i < 3; i++ {
		if _, err := sink.AppendActionTransitionAudit(ctx, actionAuditEvent(tenant, fmt.Sprintf("act_000000000000010%d", i), "executing", "succeeded")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// A signed checkpoint over the current chain (last_seq=3), then export.
	last, err := sink.PersistActionAuditCheckpoint(ctx, tenant)
	if err != nil || last != 3 {
		t.Fatalf("persist checkpoint = %d err=%v, want 3", last, err)
	}
	if err := sink.DetectActionAuditTruncation(ctx, tenant); err != nil {
		t.Fatalf("truncation reported for an intact chain: %v", err)
	}
	pkg, err := sink.ExportActionAuditPackage(ctx, tenant)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := audit.VerifyPackage(pkg, keys); err != nil {
		t.Fatalf("exported bundle does not verify: %v", err)
	}

	// Plant a VALIDLY-SIGNED checkpoint proving 5 events once existed. The live
	// chain (head=3) is now truncated below it - a restored/replicated chain that
	// lost its tail.
	planted := signedBatchRootParams(t, ctx, signer, tenant, "auditroot_planted", 1, 5, 5)
	if _, err := db.New(pool).InsertAuditBatchRoot(ctx, planted); err != nil {
		t.Fatalf("plant checkpoint: %v", err)
	}
	if err := sink.DetectActionAuditTruncation(ctx, tenant); !errors.Is(err, audit.ErrTruncated) {
		t.Fatalf("truncation not detected: %v, want audit.ErrTruncated", err)
	}
}

// signedBatchRootParams builds a batch-root checkpoint validly signed by the
// signer over the canonical batch pre-image.
func signedBatchRootParams(t *testing.T, ctx context.Context, signer *audit.Ed25519AuditSigner, tenant, id string, first, last, count int64) db.InsertAuditBatchRootParams {
	t.Helper()
	rootHash := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	batch := sdkaudit.BatchRoot{TenantRef: tenant, FirstSeq: uint64(first), LastSeq: uint64(last), EventCount: int(count), RootHash: rootHash, SignedAt: time.Now().UTC()}
	canonical, err := sdkaudit.CanonicalBatchRoot(batch)
	if err != nil {
		t.Fatalf("canonical batch: %v", err)
	}
	sig, err := signer.Sign(ctx, canonical)
	if err != nil {
		t.Fatalf("sign batch: %v", err)
	}
	return db.InsertAuditBatchRootParams{
		ID: id, EnterpriseID: tenant, RootHash: rootHash, FirstSeq: first, LastSeq: last, EventCount: count,
		SignedAt:           pgtype.Timestamptz{Time: batch.SignedAt, Valid: true},
		SignatureAlgorithm: sig.Algorithm, SignatureKeyID: sig.KeyID, SignatureValue: sig.Value,
	}
}

// TestDetectTruncationRejectsUnverifiedCheckpoint proves the checkpoint-signature
// guard: a persisted checkpoint whose signature does NOT verify against the
// registered key (a forgery inserted by a DB role to mask truncation) is
// REJECTED rather than silently trusted.
func TestDetectTruncationRejectsUnverifiedCheckpoint(t *testing.T) {
	pool := auditSigningPool(t)
	ctx := context.Background()
	tenant := "ent_badcheckpoint"
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1,$2)`, tenant, "Bad Co"); err != nil {
		t.Fatalf("seed enterprise: %v", err)
	}
	signer, _ := newAuditSigner(t, "audit-bad-1")
	if _, err := db.New(pool).UpsertAuditSigningKey(ctx, db.UpsertAuditSigningKeyParams{KeyID: signer.KeyID(), Algorithm: audit.SignatureAlgorithmEd25519, PublicKey: signer.PublicKey()}); err != nil {
		t.Fatalf("register key: %v", err)
	}
	sink := NewPostgresBrowserAuditSink(pool, WithAuditSigner(signer))
	for i := 0; i < 3; i++ {
		if _, err := sink.AppendActionTransitionAudit(ctx, actionAuditEvent(tenant, fmt.Sprintf("act_00000000000003%02d", i), "executing", "succeeded")); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	// Forge a checkpoint under the REGISTERED key id (the FK requires it) but with
	// a signature made by a DIFFERENT key - it will not verify. last_seq=3 would
	// otherwise mask truncation (head==3 ⇒ "no truncation") if trusted blindly.
	forged := signedBatchRootParams(t, ctx, signer, tenant, "auditroot_forged", 1, 3, 3)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	wrongSigner, _ := audit.NewEd25519AuditSigner(signer.KeyID(), wrongPriv)
	batch := sdkaudit.BatchRoot{TenantRef: tenant, FirstSeq: 1, LastSeq: 3, EventCount: 3, RootHash: forged.RootHash, SignedAt: forged.SignedAt.Time}
	canonical, _ := sdkaudit.CanonicalBatchRoot(batch)
	wrongSig, _ := wrongSigner.Sign(ctx, canonical)
	forged.SignatureValue = wrongSig.Value // valid base64, wrong key ⇒ verification fails
	if _, err := db.New(pool).InsertAuditBatchRoot(ctx, forged); err != nil {
		t.Fatalf("insert forged checkpoint: %v", err)
	}

	err := sink.DetectActionAuditTruncation(ctx, tenant)
	if err == nil {
		t.Fatal("a forged (non-verifying) checkpoint was TRUSTED; truncation detection must reject it")
	}
	if !errors.Is(err, sdkaudit.ErrBadSignature) {
		t.Fatalf("forged checkpoint rejected with %v, want ErrBadSignature", err)
	}
}

// TestConcurrentAuditWritersAllocateDistinctSequence proves the per-enterprise
// advisory lock serializes sequence allocation: many racing writers produce a
// strict 1..N sequence with no duplicate and no gap (the partial unique index is
// the database backstop; a duplicate would error).
func TestConcurrentAuditWritersAllocateDistinctSequence(t *testing.T) {
	pool := auditSigningPool(t)
	ctx := context.Background()
	tenant := "ent_race"
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1,$2)`, tenant, "Race Co"); err != nil {
		t.Fatalf("seed enterprise: %v", err)
	}
	signer, keys := newAuditSigner(t, "audit-race-1")
	sink := NewPostgresBrowserAuditSink(pool, WithAuditSigner(signer))

	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := sink.AppendActionTransitionAudit(ctx, actionAuditEvent(tenant, fmt.Sprintf("act_00000000000002%02d", n), "executing", "succeeded"))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent append failed: %v", err)
		}
	}
	chain := readSignedChain(t, ctx, pool, tenant)
	if len(chain) != writers {
		t.Fatalf("chain len = %d, want %d", len(chain), writers)
	}
	for i, e := range chain {
		if e.TenantSeq != uint64(i+1) {
			t.Fatalf("event %d tenant_seq = %d, want %d (gap/duplicate under contention)", i, e.TenantSeq, i+1)
		}
	}
	if err := audit.Verify(chain, keys); err != nil {
		t.Fatalf("concurrently-written chain does not verify: %v", err)
	}
}

func keysList(set sdkaudit.KeySet) []audit.SigningKey {
	out := make([]audit.SigningKey, 0, len(set))
	for _, k := range set {
		out = append(out, k)
	}
	return out
}
