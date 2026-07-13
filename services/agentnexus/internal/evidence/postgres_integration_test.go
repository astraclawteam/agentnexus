package evidence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests are DSN-gated: they run only when a PostgreSQL DSN is
// provided and skip cleanly otherwise (no PostgreSQL on CI developer hosts).
// Migration 000008 is self-contained (its tables reference only each other),
// so the fixture applies it directly.
//
// WARNING: the target database is mutated (the fixture drops and recreates
// the evidence_* tables). Point AGENTNEXUS_E2E_POSTGRES_DSN at a disposable
// database.

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN (or AGENTNEXUS_POSTGRES_DSN) to run the evidence postgres integration tests")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	// Simple protocol lets the fixture exec the multi-statement goose block
	// (including the plpgsql $$ trigger bodies) in one call.
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// gooseBlock extracts the Up or Down statement block from the goose migration.
func gooseBlock(t *testing.T, direction string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", "000008_evidence_handles.sql"))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(raw)
	marker := "-- +goose " + direction
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("migration is missing %q", marker)
	}
	segment := text[start:]
	begin := strings.Index(segment, "-- +goose StatementBegin")
	end := strings.Index(segment, "-- +goose StatementEnd")
	if begin < 0 || end < 0 || end < begin {
		t.Fatalf("migration %s block is malformed", direction)
	}
	return segment[begin+len("-- +goose StatementBegin") : end]
}

func applyMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, gooseBlock(t, "Down")); err != nil {
		t.Fatalf("migration down (pre-clean): %v", err)
	}
	if _, err := pool.Exec(ctx, gooseBlock(t, "Up")); err != nil {
		t.Fatalf("migration up: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), gooseBlock(t, "Down"))
		pool.Close()
	})
}

type pgFixture struct {
	pool      *pgxpool.Pool
	store     *PostgresStore
	objects   *FileObjectStore
	source    *MemoryContentSource
	snapshots *policy.MemorySnapshotSource
	audit     *recordingAuditSink
	now       *time.Time
	newSvc    func() *Service
	svc       *Service
}

func newPostgresFixture(t *testing.T) *pgFixture {
	t.Helper()
	pool := integrationPool(t)
	applyMigration(t, pool)
	objects, err := NewFileObjectStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileObjectStore: %v", err)
	}
	now := time.Date(2026, 7, 14, 10, 0, 0, 0, time.UTC)
	f := &pgFixture{
		pool:      pool,
		store:     NewPostgresStore(pool),
		objects:   objects,
		source:    NewMemoryContentSource(),
		snapshots: policy.NewMemorySnapshotSource(),
		audit:     &recordingAuditSink{},
		now:       &now,
	}
	f.snapshots.StoreSnapshot(testTenant, testActor, policy.SealedAccessSnapshot{
		TenantRef: testTenant, OrgVersion: 7,
		OrgUnits:    []policy.SealedOrgUnit{{ID: "root"}},
		Memberships: []policy.SealedMembership{{OrgUnitID: "root", Role: "suggest"}},
	})
	f.newSvc = func() *Service {
		return NewService(f.store, f.objects, testKeyProvider(), f.source,
			policy.NewCapabilityEvaluator(f.snapshots), f.audit,
			WithClock(func() time.Time { return *f.now }),
		)
	}
	f.svc = f.newSvc()
	return f
}

func (f *pgFixture) principal() runtime.PrincipalContext {
	now := *f.now
	return runtime.PrincipalContext{
		TenantRef: testTenant, PrincipalRef: testActor, AgentClientRef: "console",
		AgentReleaseRef: "unregistered", TrustClass: runtime.TrustFirstParty,
		OrgSnapshotRef: "orgv_7", VerifiedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func (f *pgFixture) locate(t *testing.T, requestID string) (LocateResult, runtime.EvidenceHandle) {
	t.Helper()
	result, err := f.svc.Locate(context.Background(), f.principal(), fullAuthz(), runtime.EvidenceRequest{
		RequestID: requestID,
		DataNeeds: []runtime.DataNeed{{NeedID: "n-" + requestID, DataClass: connectorClass, Purpose: testPurpose}},
		Purpose:   testPurpose,
		ExpiresAt: f.now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("Locate evidence = %d, want 1", len(result.Evidence))
	}
	return result, result.Evidence[0]
}

func (f *pgFixture) read(t *testing.T, svc *Service, businessContextRef, evidenceRef string) ReadResult {
	t.Helper()
	read, err := svc.Read(context.Background(), f.principal(), fullAuthz(), runtime.EvidenceReadRequest{
		RequestID: "read-" + evidenceRef, BusinessContextRef: businessContextRef,
		EvidenceRef: evidenceRef, Purpose: testPurpose, ExpiresAt: f.now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return read
}

func TestEvidencePostgresLifecycleWithDurableInvalidation(t *testing.T) {
	f := newPostgresFixture(t)
	ctx := context.Background()
	if _, err := f.svc.RegisterSourceBinding(ctx, SourceBinding{
		TenantRef: testTenant, DataClass: connectorClass,
		SourceRef: connectorCanary + connectorPathCanary, SourceVersion: 3,
		AccessCapability: "knowledge.suggest", SourceCapability: "connector.hr.read",
		ResourceType: "knowledge", ResourceID: "hr-directory", CachedReadAllowed: true,
	}); err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	f.source.Seed(connectorCanary+connectorPathCanary, []Record{{"note": contentCanary}, {"note": "plain"}})

	result, handle := f.locate(t, "pg-req-1")
	if read := f.read(t, f.svc, result.BusinessContextRef, handle.EvidenceRef); read.Decision != DecisionAllow || read.SourceVersion != 3 || !read.ServedFromCache {
		t.Fatalf("durable read = %+v, want allow at source version 3 from cache", read)
	}

	// Cross-tenant isolation through the REAL SQL predicates: the same handle
	// does not resolve under another tenant (a dropped tenant_ref predicate in
	// the queries would surface here, which MemoryStore tests cannot see).
	foreign := f.principal()
	foreign.TenantRef = "ten_other"
	crossTenant, err := f.svc.Read(ctx, foreign, fullAuthz(), runtime.EvidenceReadRequest{
		RequestID: "pg-cross-tenant", BusinessContextRef: result.BusinessContextRef,
		EvidenceRef: handle.EvidenceRef, Purpose: testPurpose, ExpiresAt: f.now.Add(2 * time.Hour),
	})
	if err != nil || crossTenant.Decision != DecisionDeny || crossTenant.Data != nil {
		t.Fatalf("cross-tenant durable read = (%+v, %v), want bare deny", crossTenant, err)
	}

	// Source-version invalidation is durable and fails stale reads closed.
	if _, err := f.svc.InvalidateSourceVersion(ctx, testTenant, connectorClass); err != nil {
		t.Fatalf("InvalidateSourceVersion: %v", err)
	}
	if read := f.read(t, f.svc, result.BusinessContextRef, handle.EvidenceRef); read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("stale read after durable invalidation = %+v, want bare deny", read)
	}

	// A fresh locate binds the bumped version; revocation then propagates.
	result2, handle2 := f.locate(t, "pg-req-2")
	if read := f.read(t, f.svc, result2.BusinessContextRef, handle2.EvidenceRef); read.Decision != DecisionAllow || read.SourceVersion != 4 {
		t.Fatalf("fresh read = %+v, want allow at source version 4", read)
	}
	if err := f.svc.RevokeAuthorization(ctx, testTenant, handle2.EvidenceRef, "operator revocation"); err != nil {
		t.Fatalf("RevokeAuthorization: %v", err)
	}

	// Restart/resume: a NEW service and a NEW store over the same database
	// keep every revocation and invalidation decision.
	restartedStore := NewPostgresStore(f.pool)
	restarted := NewService(restartedStore, f.objects, testKeyProvider(), f.source,
		policy.NewCapabilityEvaluator(f.snapshots), f.audit,
		WithClock(func() time.Time { return *f.now }),
	)
	if read := f.read(t, restarted, result2.BusinessContextRef, handle2.EvidenceRef); read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("revoked read after restart = %+v, want bare deny", read)
	}
	if read := f.read(t, restarted, result.BusinessContextRef, handle.EvidenceRef); read.Decision != DecisionDeny {
		t.Fatalf("stale read after restart = %+v, want deny", read)
	}

	// The append-only handle event log rejects mutation (trigger-enforced).
	if _, err := f.pool.Exec(ctx, `UPDATE evidence_handle_events SET reason = 'tampered'`); err == nil {
		t.Fatal("evidence_handle_events accepted an UPDATE; the log must be append-only")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE evidence_handles SET content_hash = repeat('0', 64)`); err == nil {
		t.Fatal("evidence_handles accepted an UPDATE; issued handles are immutable")
	}

	// Source deletion is durable and denies future locates.
	if err := f.svc.DeleteSource(ctx, testTenant, connectorClass); err != nil {
		t.Fatalf("DeleteSource: %v", err)
	}
	if _, err := f.svc.Locate(ctx, f.principal(), fullAuthz(), runtime.EvidenceRequest{
		RequestID: "pg-req-3",
		DataNeeds: []runtime.DataNeed{{NeedID: "n3", DataClass: connectorClass, Purpose: testPurpose}},
		Purpose:   testPurpose, ExpiresAt: f.now.Add(time.Hour),
	}); err == nil {
		t.Fatal("locate on a deleted source must fail closed")
	}
}

func TestEvidencePostgresRetentionSweepKeepsAuditableMetadata(t *testing.T) {
	f := newPostgresFixture(t)
	ctx := context.Background()
	if _, err := f.svc.RegisterSourceBinding(ctx, SourceBinding{
		TenantRef: testTenant, DataClass: connectorClass,
		SourceRef: connectorCanary + connectorPathCanary, SourceVersion: 3,
		AccessCapability: "knowledge.suggest", SourceCapability: "connector.hr.read",
		ResourceType: "knowledge", ResourceID: "hr-directory",
		CachedReadAllowed: true, RetentionTTL: 30 * time.Minute,
	}); err != nil {
		t.Fatalf("RegisterSourceBinding: %v", err)
	}
	f.source.Seed(connectorCanary+connectorPathCanary, []Record{{"note": contentCanary}})

	result, handle := f.locate(t, "pg-ret-1")
	*f.now = f.now.Add(31 * time.Minute)
	removed, err := f.svc.SweepRetention(ctx, testTenant)
	if err != nil || removed != 1 {
		t.Fatalf("SweepRetention = (%d, %v), want 1", removed, err)
	}
	if read := f.read(t, f.svc, result.BusinessContextRef, handle.EvidenceRef); read.Decision != DecisionDeny || read.Data != nil {
		t.Fatalf("read after retention sweep = %+v, want bare deny", read)
	}
	stored, err := f.store.GetHandle(ctx, testTenant, handle.EvidenceRef)
	if err != nil || len(stored.ContentHash) != 64 {
		t.Fatalf("handle metadata must survive retention: (%+v, %v)", stored, err)
	}
	events, err := f.store.ListHandleEvents(ctx, testTenant, handle.EvidenceRef)
	if err != nil || len(events) == 0 || events[len(events)-1].Kind != HandleEventContentExpired {
		t.Fatalf("content_expired event must persist: (%+v, %v)", events, err)
	}
	// Idempotent second sweep.
	if removed, err := f.svc.SweepRetention(ctx, testTenant); err != nil || removed != 0 {
		t.Fatalf("second sweep = (%d, %v), want 0", removed, err)
	}
}
