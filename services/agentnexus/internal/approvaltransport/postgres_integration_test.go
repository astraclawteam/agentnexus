package approvaltransport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	stdruntime "runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Integration tests are DSN-gated: they run only when a PostgreSQL DSN is
// provided and skip cleanly otherwise (no PostgreSQL on developer CI hosts).
// Each test runs in a freshly-created isolated schema with the FULL
// migration chain applied (000009 drops legacy resolver tables whose parents
// come from earlier migrations, so the chain is applied as in production).
//
// WARNING: point AGENTNEXUS_E2E_POSTGRES_DSN at a disposable database.

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN (or AGENTNEXUS_POSTGRES_DSN) to run the approvaltransport postgres integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	schema := fmt.Sprintf("agentnexus_apt_%d", time.Now().UnixNano())
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
	names := make([]string, 0)
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

func tableExists(t *testing.T, pool *pgxpool.Pool, table string) bool {
	t.Helper()
	var regclass *string
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1)::text`, table).Scan(&regclass); err != nil {
		t.Fatalf("to_regclass(%s): %v", table, err)
	}
	return regclass != nil
}

func TestApprovalTransportPostgresLifecycle(t *testing.T) {
	pool := integrationPool(t)
	applyAllMigrations(t, pool)
	ctx := context.Background()

	// Retirement: the legacy resolution tables are gone, the transmission
	// tables exist.
	for _, gone := range []string{"approval_resolution_idempotency", "approval_queue_items", "enterprise_approval_policies", "enterprise_approval_policy_versions"} {
		if tableExists(t, pool, gone) {
			t.Fatalf("legacy table %s still exists after migration 000009", gone)
		}
	}
	for _, present := range []string{"approval_transmissions", "approval_delivery_attempts", "approval_evidence_records", "approval_transmission_revocations"} {
		if !tableExists(t, pool, present) {
			t.Fatalf("transmission table %s missing after migration 000009", present)
		}
	}

	store := NewPostgresStore(pool)
	audit := NewMemoryAuditSink()
	channel := NewMemoryChannel()
	service, err := NewService(store, channel, audit)
	if err != nil {
		t.Fatal(err)
	}
	principal := testPrincipal(runtime.TrustFirstParty)
	principal.VerifiedAt = time.Now().UTC().Add(-time.Minute)
	principal.ExpiresAt = time.Now().UTC().Add(time.Hour)
	request := testApprovalRequest()
	request.ExpiresAt = time.Now().UTC().Add(30 * time.Minute)

	transmission, err := service.Transmit(ctx, principal, request)
	if err != nil {
		t.Fatal(err)
	}
	if transmission.Status != StatusDelivered || transmission.DeliveryAttempts != 1 {
		t.Fatalf("transmission=%+v", transmission)
	}

	evidence := testEvidence()
	evidence.DecidedAt = time.Now().UTC()
	record, err := service.RecordEvidence(ctx, principal, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if record.AuditRefID == "" || record.EvidenceHash == "" {
		t.Fatalf("record=%+v", record)
	}
	if _, err := service.RecordEvidence(ctx, principal, evidence); err != nil {
		t.Fatalf("identical duplicate evidence rejected: %v", err)
	}
	mutated := evidence
	mutated.Decision = runtime.ApprovalDenied
	if _, err := service.RecordEvidence(ctx, principal, mutated); !errors.Is(err, ErrEvidenceReplay) {
		t.Fatalf("mutated replay err=%v", err)
	}

	status, err := service.GetStatus(ctx, principal, request.Plan.PlanRef)
	if err != nil || status.Status != StatusEvidenceRecorded || status.Decision != runtime.ApprovalApproved {
		t.Fatalf("status=%+v err=%v", status, err)
	}

	// Database-level invariants: status regression, binding mutation, attempt
	// mutation and evidence mutation are rejected by triggers.
	if _, err := pool.Exec(ctx, `UPDATE approval_transmissions SET status='pending' WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("status regression accepted by the database")
	}
	if _, err := pool.Exec(ctx, `UPDATE approval_transmissions SET parameter_hash='sha256:9999999999999999999999999999999999999999999999999999999999999999' WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("binding mutation accepted by the database")
	}
	if _, err := pool.Exec(ctx, `UPDATE approval_delivery_attempts SET outcome='failed' WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("delivery-attempt mutation accepted by the database")
	}
	if _, err := pool.Exec(ctx, `UPDATE approval_evidence_records SET decision='denied' WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("evidence mutation accepted by the database")
	}
	// The single legal evidence update is the Task 0F consumption stamp, once.
	if _, err := pool.Exec(ctx, `UPDATE approval_evidence_records SET consumed_at=now() WHERE plan_ref=$1`, request.Plan.PlanRef); err != nil {
		t.Fatalf("0F consumption stamp rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE approval_evidence_records SET consumed_at=now() WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("second consumption stamp accepted by the database (replay gate broken)")
	}
	// M3 defense-in-depth: a recorded decision timestamp is frozen and the
	// attempt counter never decreases.
	if _, err := pool.Exec(ctx, `UPDATE approval_transmissions SET decided_at=now() WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("decided_at mutation accepted by the database")
	}
	if _, err := pool.Exec(ctx, `UPDATE approval_transmissions SET delivery_attempts=0 WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("delivery_attempts decrement accepted by the database")
	}

	revoked, err := service.Revoke(ctx, principal, request.Plan.PlanRef, "operator withdrew the change")
	if err != nil || revoked.Status != StatusRevoked {
		t.Fatalf("revoked=%+v err=%v", revoked, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM approval_transmissions WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("transmission delete accepted by the database")
	}
	if _, err := pool.Exec(ctx, `UPDATE approval_transmissions SET revocation_reason='rewritten' WHERE plan_ref=$1`, request.Plan.PlanRef); err == nil {
		t.Fatal("revocation reason mutation accepted by the database")
	}
}

func TestApprovalTransportMigrationReplay(t *testing.T) {
	pool := integrationPool(t)
	applyAllMigrations(t, pool)
	ctx := context.Background()

	// 000009 Down restores the faithful post-000005 legacy state.
	if _, err := pool.Exec(ctx, gooseBlock(t, "000009_approval_transmission.sql", "Down")); err != nil {
		t.Fatalf("000009 down: %v", err)
	}
	for _, restored := range []string{"approval_resolution_idempotency", "approval_queue_items", "enterprise_approval_policies", "enterprise_approval_policy_versions"} {
		if !tableExists(t, pool, restored) {
			t.Fatalf("legacy table %s missing after 000009 down", restored)
		}
	}
	for _, gone := range []string{"approval_transmissions", "approval_delivery_attempts", "approval_evidence_records", "approval_transmission_revocations"} {
		if tableExists(t, pool, gone) {
			t.Fatalf("transmission table %s still exists after 000009 down", gone)
		}
	}

	// Up again: the retirement replays cleanly.
	if _, err := pool.Exec(ctx, gooseBlock(t, "000009_approval_transmission.sql", "Up")); err != nil {
		t.Fatalf("000009 up (replay): %v", err)
	}
	for _, gone := range []string{"approval_resolution_idempotency", "approval_queue_items", "enterprise_approval_policies", "enterprise_approval_policy_versions"} {
		if tableExists(t, pool, gone) {
			t.Fatalf("legacy table %s still exists after 000009 up replay", gone)
		}
	}
	if !tableExists(t, pool, "approval_transmissions") {
		t.Fatal("approval_transmissions missing after 000009 up replay")
	}
}

// applyMigrationsBelow applies every migration strictly below stop (lexical
// order) — used to stage the pre-000009 legacy state.
func applyMigrationsBelow(t *testing.T, pool *pgxpool.Pool, stop string) {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") && entry.Name() < stop {
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

// TestApprovalTransportMigrationRefusesLegacyEvidenceDrop drives the 000009
// pre-release refusal guard for real: with a row present in the legacy
// approval_resolution_idempotency table, the Up migration must RAISE instead
// of silently dropping decision evidence. The seed disables only the legacy
// resolver's USER triggers (route-evidence validators) on the retired tables
// to plant the row; CHECK and FK constraints remain enforced.
func TestApprovalTransportMigrationRefusesLegacyEvidenceDrop(t *testing.T) {
	pool := integrationPool(t)
	applyMigrationsBelow(t, pool, "000009")
	ctx := context.Background()
	parents := `
INSERT INTO enterprises(id,name) VALUES ('ent_guard','Guard');
INSERT INTO enterprise_users(id,enterprise_id,display_name) VALUES ('u_req','ent_guard','Requester');
INSERT INTO org_units(id,enterprise_id,parent_id,name,unit_type) VALUES ('unit_g','ent_guard',NULL,'Guard','company');
INSERT INTO org_events(id,enterprise_id,event_type,source_hash) VALUES ('ev_g','ent_guard','guard','sha256:guard');
INSERT INTO org_versions(id,enterprise_id,version_number,source_event_id) VALUES ('ver_g','ent_guard',1,'ev_g');
INSERT INTO org_policy_snapshot_units(enterprise_id,version_number,org_unit_id,parent_id) VALUES ('ent_guard',1,'unit_g',NULL);
UPDATE org_versions SET policy_snapshot_sealed=true WHERE enterprise_id='ent_guard' AND version_number=1;
INSERT INTO enterprise_approval_policies(enterprise_id,minimum_risk,max_low_impacted_users,max_low_impacted_org_units,policy_version) VALUES ('ent_guard','low',25,1,1);
INSERT INTO audit_events(id,enterprise_id,action,decision,event_hash) VALUES ('ae_guard','ent_guard','approval.route.resolve','single_confirmation','sha256:guardhash')`
	if _, err := pool.Exec(ctx, parents); err != nil {
		t.Fatalf("seed legacy parents: %v", err)
	}
	// The INSERT runs in its own transaction: its DEFERRED RI trigger events
	// must settle at commit before a later ENABLE TRIGGER can run.
	if _, err := pool.Exec(ctx, `ALTER TABLE approval_resolution_idempotency DISABLE TRIGGER USER`); err != nil {
		t.Fatalf("disable legacy validators: %v", err)
	}
	legacyRow := `INSERT INTO approval_resolution_idempotency(
    enterprise_id, idempotency_key_hash, request_hash, requester_user_id, org_version, org_unit_id,
    policy_version, policy_version_ref, resource_type, resource_id, action, route_mode, risk_level,
    risk_reasons, requester_permission, requester_permission_org_unit_id, org_path,
    audit_event_id, expected_audit_input_hash, expected_audit_output_hash
) VALUES (
    'ent_guard', repeat('a',64), repeat('b',64), 'u_req', 1, 'unit_g',
    1, 1, 'knowledge', 'k1', 'knowledge.publish_low_risk', 'single_confirmation', 'low',
    '["explicit_confirmation_required"]', 'publish_low_risk', 'unit_g', '["unit_g"]',
    'ae_guard', repeat('c',64), repeat('d',64)
)`
	if _, err := pool.Exec(ctx, legacyRow); err != nil {
		t.Fatalf("seed legacy evidence row: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE approval_resolution_idempotency ENABLE TRIGGER USER`); err != nil {
		t.Fatalf("re-enable legacy validators: %v", err)
	}
	_, err := pool.Exec(ctx, gooseBlock(t, "000009_approval_transmission.sql", "Up"))
	if err == nil {
		t.Fatal("000009 dropped a non-empty legacy evidence table without raising")
	}
	if !strings.Contains(err.Error(), "contains rows") {
		t.Fatalf("000009 refusal error=%v want the 'contains rows' guard", err)
	}
	if !tableExists(t, pool, "approval_resolution_idempotency") {
		t.Fatal("the refused migration must leave the legacy evidence table in place")
	}
	if tableExists(t, pool, "approval_transmissions") {
		t.Fatal("the refused migration must not leave transmission tables behind")
	}
}

// TestApprovalTransportPerPlanLockSerializes proves the two-parameter
// advisory lock (C1 fix shape) actually serializes per plan on real
// PostgreSQL and does NOT serialize across different plans.
func TestApprovalTransportPerPlanLockSerializes(t *testing.T) {
	pool := integrationPool(t)
	applyAllMigrations(t, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const lockSQL = `SELECT pg_advisory_xact_lock(hashtext('apt:' || $1::text), hashtext($2::text))`
	first, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Rollback(context.Background()) }()
	if _, err := first.Exec(ctx, lockSQL, "ent-1", testPlanRef); err != nil {
		t.Fatalf("first acquisition: %v", err)
	}
	second, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Rollback(context.Background()) }()
	// A different plan under the same tenant is NOT blocked (per-plan
	// granularity).
	if _, err := second.Exec(ctx, lockSQL, "ent-1", "apl_fedcba9876543210"); err != nil {
		t.Fatalf("different-plan acquisition blocked: %v", err)
	}
	if err := second.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	blockedTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockedTx.Rollback(context.Background()) }()
	blocked, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_, blockErr := blockedTx.Exec(blocked, lockSQL, "ent-1", testPlanRef)
	stop()
	if !errors.Is(blockErr, context.DeadlineExceeded) && !errors.Is(blockErr, context.Canceled) {
		t.Fatalf("same-plan second acquisition returned non-timeout error: %v", blockErr)
	}
	_ = blockedTx.Rollback(context.Background())
	if err := first.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	release, done := context.WithTimeout(context.Background(), 2*time.Second)
	defer done()
	if _, err := pool.Exec(release, lockSQL, "ent-1", testPlanRef); err != nil {
		t.Fatalf("acquisition after release failed: %v", err)
	}
}
