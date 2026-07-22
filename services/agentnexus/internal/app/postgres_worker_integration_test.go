package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The connector worker's execution seams, composed the way cmd/connector-worker
// composes them, against REAL PostgreSQL. This suite exists because the wiring it
// covers is invisible from inside every package that owns a piece of it: the
// worker package cannot see whether anyone constructs its resolver, the actions
// package cannot see whether anyone builds a service for the worker, and a unit
// test of either would supply its own fake and never observe the production
// value.
//
// It is DSN-gated and skips cleanly, like every other integration suite here.

func workerSeamsPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return auditSigningPool(t)
}

func workerSeamsConfig(t *testing.T) PostgresWorkerConfig {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PostgresWorkerConfig{ReceiptSigningKeyID: "connector-worker-receipt-test", ReceiptSigningKey: key}
}

func workerTestIdentity() worker.Identity {
	return worker.Identity{
		PrincipalRef: "connector-worker", AgentClientRef: "agc_test",
		AgentReleaseRef: "agr_test", OrgSnapshotRef: "orgv_test",
	}
}

// THE measurable outcome of task B1. Every seam with a production implementation
// is composed, so the wiring guard names ONLY the ObservationProducer — the one
// dependency that has no implementation anywhere in this build.
//
// Asserting the exact set, not just "shorter", is the point: a subset assertion
// would still pass if the resolver quietly stopped being wired, which is the
// regression this whole guard exists to catch.
func TestPostgresWorkerSeamsLeaveOnlyTheObservationProducerUnwired(t *testing.T) {
	pool := workerSeamsPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seams, err := NewPostgresWorkerSeams(ctx, pool, workerSeamsConfig(t))
	if err != nil {
		t.Fatalf("NewPostgresWorkerSeams: %v", err)
	}
	seams.Identity = workerTestIdentity()

	missing := seams.MissingRequired()
	if len(missing) != 1 || missing[0] != "Observations" {
		t.Fatalf("MissingRequired() = %v, want exactly [Observations]", missing)
	}
	// The worker still must NOT become ready. If this ever passes, the
	// ObservationProducer was wired without this assertion being revisited — and
	// a ready worker with the nil HostFactory this build ships would nak every
	// intent it pulled. See the note on NewPostgresWorkerSeams.
	executionWorker, err := worker.New(seams)
	if err != nil {
		t.Fatalf("worker.New refused a config with an action plane and a full identity: %v", err)
	}
	if err := executionWorker.CheckReady(ctx); err == nil {
		t.Fatal("CheckReady accepted a worker with no observation producer")
	}
}

// The signer and the key registration are composed together on purpose. This is
// the assertion that proves they agree: a receipt signed by the returned Signer
// verifies through the SAME registry-backed resolver the returned Actions plane
// uses to decide whether a receipt may complete an Action.
//
// Without the registration the signature would resolve to no key and every
// completion would fail closed — a worker that signs receipts its own action
// service then rejects.
func TestPostgresWorkerSeamsSignReceiptsTheActionPlaneCanVerify(t *testing.T) {
	pool := workerSeamsPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seams, err := NewPostgresWorkerSeams(ctx, pool, workerSeamsConfig(t))
	if err != nil {
		t.Fatalf("NewPostgresWorkerSeams: %v", err)
	}
	parameters := []byte(`{"amount":1}`)
	sum := sha256.Sum256(parameters)
	action := actions.Action{
		ActionRef: "act_b1workerseamsfixture", Capability: "billing.invoice.issue",
		ParameterHash:         "sha256:" + hex.EncodeToString(sum[:]),
		ExpectedReceiptSchema: "receipt.v1",
	}
	receipt, err := worker.BuildSignedActionReceipt(ctx, seams.Signer,
		func(prefix string) string { return prefix + "b1workerseamsfixture" },
		func() time.Time { return time.Now().UTC() },
		action, runtime.StatusSucceeded, host.Result{})
	if err != nil {
		t.Fatalf("sign a receipt with the composed signer: %v", err)
	}
	if err := actions.NewSignedReceiptVerifier(postgresSigningKeyResolver{pool: pool}).
		VerifyReceipt(ctx, action.ActionRef, receipt); err != nil {
		t.Fatalf("the composed signer produced a receipt the registry-backed verifier rejects: %v", err)
	}
}

// The resolver must have been handed the POOL, not merely constructed. A
// resolver built over a nil pool refuses with ErrNotReady before it reads
// anything; a real one over an empty binding table refuses with
// ErrBindingNotFound, which is a fact about the customer's data.
//
// Distinguishing those two refusals is the whole assertion: both are failures,
// and only one of them means the seam is actually wired.
func TestPostgresWorkerSeamsResolverReadsTheBindingTables(t *testing.T) {
	pool := workerSeamsPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seams, err := NewPostgresWorkerSeams(ctx, pool, workerSeamsConfig(t))
	if err != nil {
		t.Fatalf("NewPostgresWorkerSeams: %v", err)
	}
	_, err = seams.Resolver.Resolve(ctx, "ent_b1seamtest", "billing.invoice.issue")
	if !errors.Is(err, worker.ErrBindingNotFound) {
		t.Fatalf("Resolve() = %v, want ErrBindingNotFound from a real read of an empty binding table", err)
	}
	if errors.Is(err, worker.ErrNotReady) {
		t.Fatal("the resolver has no database pool; it was constructed but not wired")
	}
}

// Registration is idempotent, because a redeploy re-runs it. A second
// composition against the same key must not disturb the registry — the public
// half that already verifies every prior receipt has to stay exactly what it was.
func TestPostgresWorkerSeamsRegistrationIsIdempotent(t *testing.T) {
	pool := workerSeamsPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := workerSeamsConfig(t)
	if _, err := NewPostgresWorkerSeams(ctx, pool, cfg); err != nil {
		t.Fatalf("first composition: %v", err)
	}
	if _, err := NewPostgresWorkerSeams(ctx, pool, cfg); err != nil {
		t.Fatalf("a redeploy must re-register the same key without failing: %v", err)
	}
	row, err := db.New(pool).GetAuditSigningKey(ctx, cfg.ReceiptSigningKeyID)
	if err != nil {
		t.Fatalf("the receipt signing key is not in the registry: %v", err)
	}
	if !ed25519.PublicKey(row.PublicKey).Equal(cfg.ReceiptSigningKey.Public()) {
		t.Error("the registered public half is not the configured key's")
	}
}

// Unusable key material never reaches a composition. The seams are built as one
// unit deliberately: a plane composed over a signer that cannot sign would
// accept every transition attempt and fail it at the audit append.
func TestPostgresWorkerSeamsRefuseUnusableSigningKeyMaterial(t *testing.T) {
	pool := workerSeamsPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]PostgresWorkerConfig{
		"no key id": {ReceiptSigningKey: key},
		"no key":    {ReceiptSigningKeyID: "receipt-1"},
		"short key": {ReceiptSigningKeyID: "receipt-1", ReceiptSigningKey: key[:8]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPostgresWorkerSeams(ctx, pool, cfg); err == nil {
				t.Fatal("composed execution seams over a signer that cannot sign")
			}
		})
	}
}
