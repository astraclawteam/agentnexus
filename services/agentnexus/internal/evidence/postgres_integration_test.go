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
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests are DSN-gated: they run only when a PostgreSQL DSN is
// provided and skip cleanly otherwise (no PostgreSQL on CI developer hosts).
// The evidence migrations are self-contained (their tables reference only each
// other), so the fixture applies them directly; see evidenceMigrations.
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
	// Default query exec mode on purpose (approvaltransport fixture pattern):
	// pgx executes a zero-argument Exec through the simple protocol anyway, so
	// the multi-statement goose block (including the plpgsql $$ trigger bodies)
	// applies in one call, while parameterized data-path queries keep the
	// extended protocol so parameters are typed by the statement description
	// (forcing QueryExecModeSimpleProtocol pool-wide encodes the []byte
	// lineage parameter as bytea hex, which the jsonb column rejects with
	// SQLSTATE 22P02).
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// evidenceMigrations are the migrations this fixture applies, in order. 000008
// creates the evidence_* tables; 000015 adds the observation-authority columns
// its verification half needs. They are listed rather than globbed so a new
// migration elsewhere in the tree cannot silently change what these tests run
// against.
var evidenceMigrations = []string{
	"000008_evidence_handles.sql",
	"000015_evidence_source_binding_authority.sql",
}

// gooseBlock extracts the Up or Down statement block from one goose migration.
func gooseBlock(t *testing.T, file, direction string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", file))
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	text := string(raw)
	marker := "-- +goose " + direction
	start := strings.Index(text, marker)
	if start < 0 {
		t.Fatalf("migration %s is missing %q", file, marker)
	}
	segment := text[start:]
	begin := strings.Index(segment, "-- +goose StatementBegin")
	end := strings.Index(segment, "-- +goose StatementEnd")
	if begin < 0 || end < 0 || end < begin {
		t.Fatalf("migration %s %s block is malformed", file, direction)
	}
	return segment[begin+len("-- +goose StatementBegin") : end]
}

// applyMigration brings the schema up in migration order and tears it down in
// reverse. Order matters in both directions: 000015 ALTERs a table 000008
// creates, so applying it first errors and dropping 000008 first would leave
// 000015's Down with nothing to drop.
func applyMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	down := func(ctx context.Context) {
		for i := len(evidenceMigrations) - 1; i >= 0; i-- {
			_, _ = pool.Exec(ctx, gooseBlock(t, evidenceMigrations[i], "Down"))
		}
	}
	down(ctx) // pre-clean
	for _, file := range evidenceMigrations {
		if _, err := pool.Exec(ctx, gooseBlock(t, file, "Up")); err != nil {
			t.Fatalf("migration %s up: %v", file, err)
		}
	}
	t.Cleanup(func() {
		down(context.Background())
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

// TestPostgresSourceBindingRoundTripsAuthorityDeclaration is the real proof for
// migration 000015. Before it, UpsertSourceBinding REFUSED any binding carrying
// an authority declaration (there were no columns for it) and
// sourceBindingFromRow could never populate one, so over PostgreSQL every
// verification-purpose read denied at observation_authority_undeclared no matter
// what else was wired.
//
// The assertion that matters is the ROUND TRIP through real SQL. Dropping either
// column from the INSERT, the RETURNING list or sourceBindingFromRow leaves the
// upsert succeeding and the read-back silently undeclared - exactly the silent
// degradation the old refusal existed to prevent - and only reading the value
// back out of the database catches it.
func TestPostgresSourceBindingRoundTripsAuthorityDeclaration(t *testing.T) {
	f := newPostgresFixture(t)
	ctx := context.Background()

	stored, err := f.svc.RegisterSourceBinding(ctx, SourceBinding{
		TenantRef: testTenant, DataClass: connectorClass, SourceRef: "internal-source",
		SourceVersion: 1, AccessCapability: "knowledge.suggest",
		ResourceType: "knowledge", ResourceID: "erp-po-registry",
		AuthorityTier: AuthorityTierSystemOfRecord, FreshnessBound: 90 * time.Second,
	})
	if err != nil {
		t.Fatalf("RegisterSourceBinding with an authority declaration: %v", err)
	}
	if stored.AuthorityTier != AuthorityTierSystemOfRecord || stored.FreshnessBound != 90*time.Second {
		t.Fatalf("upsert returned (%q, %v), want (%q, 1m30s)",
			stored.AuthorityTier, stored.FreshnessBound, AuthorityTierSystemOfRecord)
	}

	// Re-read through a SEPARATE query. The upsert's own RETURNING could be
	// correct while the SELECT list omits the columns.
	got, err := f.store.GetSourceBinding(ctx, testTenant, connectorClass)
	if err != nil {
		t.Fatalf("GetSourceBinding: %v", err)
	}
	if got.AuthorityTier != AuthorityTierSystemOfRecord || got.FreshnessBound != 90*time.Second {
		t.Fatalf("read back (%q, %v), want (%q, 1m30s)",
			got.AuthorityTier, got.FreshnessBound, AuthorityTierSystemOfRecord)
	}

	// An undeclared binding stays undeclared: the columns default to the
	// explicit "not declared" state rather than to some tier.
	if _, err := f.svc.RegisterSourceBinding(ctx, SourceBinding{
		TenantRef: testTenant, DataClass: "hr.undeclared", SourceRef: "internal-source-2",
		SourceVersion: 1, AccessCapability: "knowledge.suggest",
		ResourceType: "knowledge", ResourceID: "hr-directory",
	}); err != nil {
		t.Fatalf("RegisterSourceBinding without a declaration: %v", err)
	}
	undeclared, err := f.store.GetSourceBinding(ctx, testTenant, "hr.undeclared")
	if err != nil {
		t.Fatalf("GetSourceBinding (undeclared): %v", err)
	}
	if undeclared.AuthorityTier != "" || undeclared.FreshnessBound != 0 {
		t.Fatalf("undeclared binding read back as (%q, %v), want empty/zero",
			undeclared.AuthorityTier, undeclared.FreshnessBound)
	}
}

// TestPostgresRejectsHalfDeclaredAuthority pins the schema's all-or-nothing
// CHECK independently of Service.RegisterSourceBinding, which applies the same
// rule in Go and would otherwise be the only thing enforcing it. The store is
// driven DIRECTLY here so the Go validation is bypassed: a tier without a bound
// is an unbounded observation and a bound without a tier is freshness under no
// declared authority, and neither may reach the table by any writer.
func TestPostgresRejectsHalfDeclaredAuthority(t *testing.T) {
	f := newPostgresFixture(t)
	ctx := context.Background()

	for _, tc := range []struct {
		name  string
		tier  string
		bound time.Duration
		class string
	}{
		{"tier without a freshness bound", AuthorityTierSystemOfRecord, 0, "hr.tier_only"},
		{"freshness bound without a tier", "", 90 * time.Second, "hr.bound_only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.store.UpsertSourceBinding(ctx, SourceBinding{
				TenantRef: testTenant, ID: "esb_" + tc.class, DataClass: tc.class,
				SourceRef: "internal", SourceVersion: 1, AccessCapability: "knowledge.suggest",
				ResourceType: "knowledge", ResourceID: "erp-po-registry",
				AuthorityTier: tc.tier, FreshnessBound: tc.bound,
			})
			if err == nil {
				t.Fatal("the schema must reject a half-declared observation authority")
			}
			if !strings.Contains(err.Error(), "chk_evidence_source_bindings_authority_declared") {
				t.Fatalf("want the all-or-nothing CHECK to reject this, got %v", err)
			}
		})
	}
}
