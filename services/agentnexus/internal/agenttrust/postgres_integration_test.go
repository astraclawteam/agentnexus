package agenttrust

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests are DSN-gated: they run only when a Postgres DSN is
// provided, and skip cleanly otherwise (no Postgres on CI developer hosts).
// Migration 000007 is self-contained (agent_certifications references only
// agent_clients, both created by 000007), so the fixture applies it directly.
//
// WARNING: the target database is mutated (the fixture drops and recreates the
// agent_* tables). Point AGENTNEXUS_E2E_POSTGRES_DSN at a disposable database.

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN (or AGENTNEXUS_POSTGRES_DSN) to run the agenttrust postgres integration tests")
	}
	// Default query exec mode on purpose (approvaltransport fixture pattern):
	// pgx executes a zero-argument Exec through the simple protocol anyway, so
	// the multi-statement goose block (including the plpgsql $$ trigger bodies)
	// applies in one call, while parameterized data-path queries keep the
	// extended protocol so parameters are typed by the statement description
	// (forcing QueryExecModeSimpleProtocol pool-wide encodes []byte jsonb
	// parameters as bytea hex and corrupts NUL-bearing text parameters at the
	// wire level, which PostgreSQL rejects).
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// gooseBlock extracts the Up or Down statement block from the goose migration.
func gooseBlock(t *testing.T, direction string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", "000007_agent_clients.sql"))
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

func integrationFixture(t *testing.T) (*Service, *PostgresStore) {
	pool := integrationPool(t)
	applyMigration(t, pool)
	store := NewPostgresStore(pool)
	svc := NewService(store)
	return svc, store
}

func TestPostgresTrustRegistryLifecycle(t *testing.T) {
	svc, _ := integrationFixture(t)
	ctx := context.Background()
	const tenant = "ten_pg"
	if _, err := svc.Register(ctx, tenant, RegisterInput{Publisher: "AgentAtlas", Product: "atlas-runtime", EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	cert, err := svc.Certify(ctx, tenant, CertifyInput{
		Publisher: "AgentAtlas", Product: "atlas-runtime",
		VersionRange:          runtime.VersionRange{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"},
		SigningKey:            runtime.SigningKey{KeyID: "key_1", Algorithm: "ed25519", PublicKey: "cHVi"},
		ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64),
		TrustClass:            runtime.TrustFirstParty, CapabilityCeiling: []string{"knowledge.create"},
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}
	release := Release{Publisher: "AgentAtlas", Product: "atlas-runtime", Version: "1.4.2", SigningKeyID: "key_1", ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64)}

	got, err := svc.Assess(ctx, tenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustFirstParty || !got.SideEffectAllowed {
		t.Fatalf("certified first-party release must be trusted: %+v", got)
	}

	// A different tenant must not inherit the certification (tenant escape).
	other, err := svc.Assess(ctx, "ten_other", AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess other tenant: %v", err)
	}
	if other.TrustClass != runtime.TrustUntrusted {
		t.Fatalf("certification leaked across tenants: %+v", other)
	}

	// Revoked release fails before any grant is issued.
	if _, err := svc.Revoke(ctx, tenant, cert.ID, "compromise"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err := svc.Assess(ctx, tenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess after revoke: %v", err)
	}
	if revoked.TrustClass != runtime.TrustUntrusted || revoked.SideEffectAllowed {
		t.Fatalf("revoked release must be untrusted before grant issuance: %+v", revoked)
	}
}

func TestPostgresConcurrentRevocationChainsLinearly(t *testing.T) {
	svc, store := integrationFixture(t)
	ctx := context.Background()
	const tenant = "ten_conc"
	if _, err := svc.Register(ctx, tenant, RegisterInput{Publisher: "PartnerCo", Product: "partner-agent", EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	cert, err := svc.Certify(ctx, tenant, CertifyInput{
		Publisher: "PartnerCo", Product: "partner-agent",
		VersionRange:          runtime.VersionRange{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"},
		SigningKey:            runtime.SigningKey{KeyID: "key_p", Algorithm: "ed25519", PublicKey: "cGs"},
		ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64),
		TrustClass:            runtime.TrustCertifiedThirdParty, CapabilityCeiling: []string{"knowledge.suggest"},
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Certify: %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Revoke(ctx, tenant, cert.ID, "concurrent")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent revoke %d: %v", i, err)
		}
	}

	// The append-only log is one active row followed by exactly `workers`
	// revocations, chained linearly (resolved by the monotonic seq, never by the
	// non-monotonic created_at) with no fork.
	log := readStatusLog(t, store, tenant, cert.ID)
	if len(log) != workers+1 {
		t.Fatalf("status log length = %d, want %d (active + %d revocations)", len(log), workers+1, workers)
	}
	if log[0].status != string(StatusActive) || log[0].prev != "" {
		t.Fatalf("first status must be active with an empty prev: %+v", log[0])
	}
	for i := 1; i < len(log); i++ {
		if log[i].status != string(StatusRevoked) {
			t.Fatalf("status %d = %q, want revoked", i, log[i].status)
		}
		if log[i].prev != log[i-1].event {
			t.Fatalf("hash chain broken at %d: prev=%s want=%s", i, log[i].prev, log[i-1].event)
		}
	}

	// After revocation the release is untrusted.
	release := Release{Publisher: "PartnerCo", Product: "partner-agent", Version: "1.1.0", SigningKeyID: "key_p", ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64)}
	got, err := svc.Assess(ctx, tenant, AssessRequest{Release: release, Capability: "knowledge.suggest", SideEffect: false})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted {
		t.Fatalf("revoked certification must be untrusted: %+v", got)
	}
}

type statusRow struct {
	status, prev, event string
	seq                 int64
}

// readStatusLog returns a certification's status log ordered by the monotonic
// seq (never by the non-monotonic created_at).
func readStatusLog(t *testing.T, store *PostgresStore, tenant, certID string) []statusRow {
	t.Helper()
	rows, err := store.pool.Query(context.Background(),
		`SELECT status, prev_hash, event_hash, seq FROM agent_certification_status_changes WHERE tenant_ref=$1 AND certification_id=$2 ORDER BY seq`,
		tenant, certID)
	if err != nil {
		t.Fatalf("query status log: %v", err)
	}
	defer rows.Close()
	var log []statusRow
	for rows.Next() {
		var r statusRow
		if err := rows.Scan(&r.status, &r.prev, &r.event, &r.seq); err != nil {
			t.Fatalf("scan: %v", err)
		}
		log = append(log, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return log
}

// TestPostgresConcurrentSupersedeVsRevokeChainsLinearly exercises the exact
// fork window: Revoke(cert1) racing Certify(v2)-supersedes-cert1. Both status
// writers must serialize on cert1's row lock and chain onto the same tail, so
// cert1's log stays a single linear chain (verified by walking prev->event and
// asserting no two rows share a predecessor), never a fork.
func TestPostgresConcurrentSupersedeVsRevokeChainsLinearly(t *testing.T) {
	svc, store := integrationFixture(t)
	ctx := context.Background()
	const tenant = "ten_race"
	if _, err := svc.Register(ctx, tenant, RegisterInput{Publisher: "AgentAtlas", Product: "atlas-runtime", EnterpriseRegistered: true}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	cert1, err := svc.Certify(ctx, tenant, CertifyInput{
		Publisher: "AgentAtlas", Product: "atlas-runtime",
		VersionRange:          runtime.VersionRange{MinInclusive: "1.0.0", MaxExclusive: "2.0.0"},
		SigningKey:            runtime.SigningKey{KeyID: "key_1", Algorithm: "ed25519", PublicKey: "cHVi"},
		ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64),
		TrustClass:            runtime.TrustFirstParty, CapabilityCeiling: []string{"knowledge.create"},
		SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Certify v1: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var revokeErr, certifyErr error
	go func() { defer wg.Done(); _, revokeErr = svc.Revoke(ctx, tenant, cert1.ID, "concurrent") }()
	go func() {
		defer wg.Done()
		_, certifyErr = svc.Certify(ctx, tenant, CertifyInput{
			Publisher: "AgentAtlas", Product: "atlas-runtime",
			VersionRange:          runtime.VersionRange{MinInclusive: "2.0.0", MaxExclusive: "3.0.0"},
			SigningKey:            runtime.SigningKey{KeyID: "key_2", Algorithm: "ed25519", PublicKey: "bmV3"},
			ReleaseManifestDigest: "sha256:" + strings.Repeat("d", 64),
			TrustClass:            runtime.TrustFirstParty, CapabilityCeiling: []string{"knowledge.create"},
			SignedBuildManifest: true, TTL: 90 * 24 * time.Hour,
		})
	}()
	wg.Wait()
	if revokeErr != nil {
		t.Fatalf("Revoke: %v", revokeErr)
	}
	if certifyErr != nil {
		t.Fatalf("Certify v2: %v", certifyErr)
	}

	log := readStatusLog(t, store, tenant, cert1.ID)
	// BOTH interleavings are valid and non-forking; the count depends on which
	// writer wins cert1's row lock (Revoke reaches the lock in ~1 round-trip,
	// Certify-v2 in ~7, so Revoke usually wins):
	//   supersede-then-revoke -> [active, superseded, revoked]  (len 3)
	//   revoke-then-supersede -> [active, revoked]              (len 2; the
	//     supersede loop correctly SKIPS the now-non-active prior)
	// The fork-prevention invariant this test exists to prove holds in BOTH: a
	// single linear chain, no two rows sharing a predecessor, terminating in a
	// non-active status. The count/status-set is asserted per interleaving; the
	// no-fork (prevSeen) and prev->event linearity assertions are unconditional.
	if len(log) != 2 && len(log) != 3 {
		t.Fatalf("cert1 status log length = %d, want 2 or 3: %+v", len(log), log)
	}
	if log[0].status != string(StatusActive) || log[0].prev != "" {
		t.Fatalf("genesis must be active with an empty prev: %+v", log[0])
	}
	prevSeen := map[string]bool{}
	statusSeen := map[string]bool{}
	for i, r := range log {
		if prevSeen[r.prev] {
			t.Fatalf("two rows chained onto the same predecessor (FORK) at %d: %+v", i, log)
		}
		prevSeen[r.prev] = true
		if i > 0 {
			if r.prev != log[i-1].event {
				t.Fatalf("hash chain broken at %d: prev=%s want=%s", i, r.prev, log[i-1].event)
			}
			if r.status != string(StatusRevoked) && r.status != string(StatusSuperseded) {
				t.Fatalf("non-genesis status %d = %q, want revoked or superseded", i, r.status)
			}
			statusSeen[r.status] = true
		}
	}
	// The chain must terminate in a non-active status regardless of ordering.
	if tail := log[len(log)-1].status; tail != string(StatusRevoked) && tail != string(StatusSuperseded) {
		t.Fatalf("chain tail = %q, want a terminal (revoked or superseded) status: %+v", tail, log)
	}
	if len(log) == 3 {
		if !statusSeen[string(StatusRevoked)] || !statusSeen[string(StatusSuperseded)] {
			t.Fatalf("a 3-row chain (supersede then revoke) must contain both a revoke and a supersede: %+v", log)
		}
	} else if !statusSeen[string(StatusRevoked)] {
		t.Fatalf("a 2-row chain must be [active, revoked] (revoke landed, supersede skipped the non-active prior): %+v", log)
	}

	release := Release{Publisher: "AgentAtlas", Product: "atlas-runtime", Version: "1.4.2", SigningKeyID: "key_1", ReleaseManifestDigest: "sha256:" + strings.Repeat("a", 64)}
	got, err := svc.Assess(ctx, tenant, AssessRequest{Release: release, Capability: "knowledge.create", SideEffect: true})
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if got.TrustClass != runtime.TrustUntrusted || got.SideEffectAllowed {
		t.Fatalf("a revoked+superseded certification must be untrusted: %+v", got)
	}
}
