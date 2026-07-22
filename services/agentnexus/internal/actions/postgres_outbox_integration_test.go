package actions

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Durable-store coverage of the transactional outbox dispatch path. These tests
// are DSN-gated exactly like the rest of the actions integration suite (see
// integrationPool) and each runs against a fresh schema with the full migration
// chain applied.
//
// They exist because the properties under test — FOR UPDATE SKIP LOCKED under
// concurrency, and which UPDATE shapes guard_action_outbox admits — live in
// PostgreSQL, not in Go. An in-memory store can model them; only the database
// can prove them.

// dispatchOnPostgres drives one fresh action from request through grant to
// dispatched against the durable store, under a distinct idempotency key.
func dispatchOnPostgres(t *testing.T, svc *Service, principal runtime.PrincipalContext, key string) Action {
	t.Helper()
	ctx := context.Background()
	req := testRequest(t)
	req.IdempotencyKey = key
	action, err := svc.RequestAction(ctx, principal, req)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, principal, action.ActionRef); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	dispatched, err := svc.Dispatch(ctx, principal, action.ActionRef)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	return dispatched
}

// outboxRow reads one outbox row's delivery accounting straight from the table.
func outboxRow(t *testing.T, pool *pgxpool.Pool, actionRef string) (published bool, attempts int, deadLettered bool, lastError string) {
	t.Helper()
	var dead *time.Time
	err := pool.QueryRow(context.Background(),
		`SELECT published, attempts, dead_lettered_at, last_error FROM action_outbox WHERE action_ref=$1`,
		actionRef).Scan(&published, &attempts, &dead, &lastError)
	if err != nil {
		t.Fatalf("read outbox row: %v", err)
	}
	return published, attempts, dead != nil, lastError
}

// TestActionPostgresDispatchPublishesAfterCommit is defect 1 on the durable
// store: the outbox row is committed first (which is what makes a crash safe)
// and then published in the same call (which is what makes the action happen).
// Nothing here waits for the recovery pump.
func TestActionPostgresDispatchPublishesAfterCommit(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	publisher := &scriptedPublisher{}
	svc := newPostgresService(t, pool, WithPublisher(publisher))
	principal := testPrincipal(runtime.TrustFirstParty)

	action := dispatchOnPostgres(t, svc, principal, "idem-pg-publish-000001")

	sent := publisher.published()
	if len(sent) != 1 || sent[0].ActionRef != action.ActionRef {
		t.Fatalf("published %+v during dispatch, want exactly the dispatched intent", sent)
	}
	published, attempts, dead, _ := outboxRow(t, pool, action.ActionRef)
	if !published {
		t.Fatal("the outbox row was not stamped published by the dispatching request")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (one delivery attempt, which succeeded)", attempts)
	}
	if dead {
		t.Fatal("a delivered intent must not be dead lettered")
	}
	// Nothing is left for the pump.
	n, err := svc.RepublishPending(ctx, principal.TenantRef)
	if err != nil || n != 0 {
		t.Fatalf("RepublishPending after a delivered dispatch = %d err=%v, want 0", n, err)
	}
	if len(publisher.published()) != 1 {
		t.Fatalf("the pump republished a delivered intent: %+v", publisher.published())
	}
}

// TestActionPostgresConcurrentPumpsClaimEachIntentExactlyOnce is defect 2 on
// the real database. The pending read now takes FOR UPDATE SKIP LOCKED and
// holds the row lock across the publish, so two pumps draining the same tenant
// concurrently DIVIDE the backlog. With an unlocked SELECT both replicas read
// the same rows and publish the whole backlog each, on every cycle.
func TestActionPostgresConcurrentPumpsClaimEachIntentExactlyOnce(t *testing.T) {
	pool := integrationPool(t)
	principal := testPrincipal(runtime.TrustFirstParty)
	// Dispatch with NO publisher wired: the whole backlog is left pending, which
	// is the state a crashed replica leaves behind.
	crashed := newPostgresService(t, pool)
	const intents = 8
	refs := make([]string, 0, intents)
	for i := 0; i < intents; i++ {
		action := dispatchOnPostgres(t, crashed, principal, fmt.Sprintf("idem-pg-concurrent-%06d", i))
		refs = append(refs, action.ActionRef)
	}
	store := NewPostgresStore(pool)
	pending, err := store.PendingDispatches(context.Background(), principal.TenantRef, 0)
	if err != nil || len(pending) != intents {
		t.Fatalf("backlog = %d err=%v, want %d", len(pending), err, intents)
	}

	// Transport latency widens the window in which both pumps hold claims.
	publisher := &scriptedPublisher{latency: 20 * time.Millisecond}
	pumps := []*Service{
		newPostgresService(t, pool, WithPublisher(publisher)),
		newPostgresService(t, pool, WithPublisher(publisher)),
	}
	counts := make([]int, len(pumps))
	errs := make([]error, len(pumps))
	var wg sync.WaitGroup
	for i, pump := range pumps {
		wg.Add(1)
		go func(i int, pump *Service) {
			defer wg.Done()
			counts[i], errs[i] = pump.RepublishPending(context.Background(), principal.TenantRef)
		}(i, pump)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("pump %d drain: %v", i, err)
		}
	}
	if total := counts[0] + counts[1]; total != intents {
		t.Fatalf("the two pumps reported %d publishes (%d + %d), want %d — each intent belongs to exactly one pump", total, counts[0], counts[1], intents)
	}
	attempted := publisher.attempted()
	if len(attempted) != intents {
		t.Fatalf("the transport saw %d deliveries, want %d — concurrent pumps duplicated the backlog", len(attempted), intents)
	}
	seen := map[string]int{}
	for _, message := range attempted {
		seen[message.DispatchRef]++
	}
	if len(seen) != intents {
		t.Fatalf("published %d distinct intents, want %d", len(seen), intents)
	}
	for ref, count := range seen {
		if count != 1 {
			t.Fatalf("dispatch %s was published %d times by concurrent pumps", ref, count)
		}
	}
	for _, ref := range refs {
		published, attempts, _, _ := outboxRow(t, pool, ref)
		if !published || attempts != 1 {
			t.Fatalf("outbox row for %s: published=%v attempts=%d, want published after exactly one attempt", ref, published, attempts)
		}
	}
}

// TestActionPostgresFailedDeliveryAccountsAttemptsThenDeadLetters is defect 3
// on the real database. It proves the widened guard_action_outbox trigger
// actually ACCEPTS the failed-attempt update shape — attempts + backoff +
// reason with published still false, which the original trigger had no legal
// form for, so a failed attempt could not be recorded at all — and that the
// drain eventually gives up and leaves the undelivered intent as evidence.
func TestActionPostgresFailedDeliveryAccountsAttemptsThenDeadLetters(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	clock := newOutboxClock()
	publisher := &scriptedPublisher{reject: func(DispatchMessage) bool { return true }}
	svc := newPostgresService(t, pool, WithPublisher(publisher), WithClock(clock.now))
	principal := testPrincipal(runtime.TrustFirstParty)

	action := dispatchOnPostgres(t, svc, principal, "idem-pg-deadletter-0001")

	published, attempts, dead, lastError := outboxRow(t, pool, action.ActionRef)
	if published || dead {
		t.Fatalf("after a failed publish: published=%v dead=%v, want both false", published, dead)
	}
	if attempts != 1 {
		t.Fatalf("attempts after the failed inline publish = %d, want 1 — the trigger must accept a failed attempt", attempts)
	}
	if lastError == "" {
		t.Fatal("the failed attempt recorded no reason")
	}

	store := NewPostgresStore(pool)
	for attempt := 2; attempt <= maxDispatchAttempts; attempt++ {
		pendingRows, err := store.PendingDispatches(ctx, principal.TenantRef, 0)
		if err != nil || len(pendingRows) != 1 {
			t.Fatalf("before attempt %d: pending=%+v err=%v, want exactly one", attempt, pendingRows, err)
		}
		clock.advance(pendingRows[0].NextAttemptAt.Sub(clock.now()) + time.Second)
		n, err := svc.RepublishPending(ctx, principal.TenantRef)
		if err != nil || n != 0 {
			t.Fatalf("drain %d = %d err=%v, want 0 published and no error", attempt, n, err)
		}
		_, got, _, _ := outboxRow(t, pool, action.ActionRef)
		if got != attempt {
			t.Fatalf("attempts after drain %d = %d, want %d", attempt, got, attempt)
		}
	}

	published, attempts, dead, _ = outboxRow(t, pool, action.ActionRef)
	if published {
		t.Fatal("a dead lettered intent must never be marked published")
	}
	if !dead {
		t.Fatalf("the intent was not dead lettered after %d attempts", maxDispatchAttempts)
	}
	if attempts != maxDispatchAttempts {
		t.Fatalf("attempts = %d, want %d", attempts, maxDispatchAttempts)
	}
	// It leaves the pending set and becomes visible undelivered evidence.
	pendingRows, err := store.PendingDispatches(ctx, principal.TenantRef, 0)
	if err != nil || len(pendingRows) != 0 {
		t.Fatalf("pending after dead lettering = %+v err=%v, want none", pendingRows, err)
	}
	deadRows, err := store.DeadLetteredDispatches(ctx, principal.TenantRef, 0)
	if err != nil || len(deadRows) != 1 || deadRows[0].ActionRef != action.ActionRef {
		t.Fatalf("dead lettered = %+v err=%v, want exactly the undelivered intent", deadRows, err)
	}
	// And it is never claimed again.
	clock.advance(24 * time.Hour)
	before := len(publisher.attempted())
	n, err := svc.RepublishPending(ctx, principal.TenantRef)
	if err != nil || n != 0 {
		t.Fatalf("drain after dead lettering = %d err=%v, want 0", n, err)
	}
	if after := len(publisher.attempted()); after != before {
		t.Fatalf("the drain retried a dead lettered intent: %d -> %d attempts", before, after)
	}
}

// TestActionPostgresOutboxRejectsIllegalUpdateShapes pins what the widened
// trigger still REFUSES, so admitting retry accounting did not quietly turn the
// outbox into a mutable table: a published row is final, a dead lettered row is
// final, the dispatch binding is immutable, and attempts cannot be rewritten to
// disarm the give-up bound.
func TestActionPostgresOutboxRejectsIllegalUpdateShapes(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	publisher := &scriptedPublisher{}
	// Both services mint handles from the SAME generator: two independent
	// sequences over one database would collide on the first action ref.
	ids := sequentialIDs()
	svc := newPostgresService(t, pool, WithPublisher(publisher), WithIDGenerator(ids))
	principal := testPrincipal(runtime.TrustFirstParty)
	delivered := dispatchOnPostgres(t, svc, principal, "idem-pg-guard-000001")

	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET published=false, published_at=NULL WHERE action_ref=$1`, delivered.ActionRef); err == nil {
		t.Fatal("un-publishing a delivered intent was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET attempts=attempts+1 WHERE action_ref=$1`, delivered.ActionRef); err == nil {
		t.Fatal("recording a further attempt on a published intent was accepted")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM action_outbox WHERE action_ref=$1`, delivered.ActionRef); err == nil {
		t.Fatal("deleting a dispatch intent was accepted")
	}

	// A pending intent: the binding is immutable and attempts may only step by
	// one, and only as part of recording a genuine failed attempt.
	stalled := newPostgresService(t, pool, WithIDGenerator(ids))
	pendingAction := dispatchOnPostgres(t, stalled, principal, "idem-pg-guard-000002")
	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET capability='erp.other.capability' WHERE action_ref=$1`, pendingAction.ActionRef); err == nil {
		t.Fatal("mutating the dispatch binding was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET attempts=0 WHERE action_ref=$1`, pendingAction.ActionRef); err == nil {
		t.Fatal("rewriting attempts was accepted; the give-up bound would be disarmable")
	}
	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET attempts=attempts+5 WHERE action_ref=$1`, pendingAction.ActionRef); err == nil {
		t.Fatal("jumping attempts by more than one attempt was accepted")
	}
	// Giving up is legal exactly once; afterwards the row is final.
	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET attempts=attempts+1, dead_lettered_at=now() WHERE action_ref=$1`, pendingAction.ActionRef); err != nil {
		t.Fatalf("recording the give-up attempt was rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET published=true, published_at=now(), attempts=attempts+1 WHERE action_ref=$1`, pendingAction.ActionRef); err == nil {
		t.Fatal("publishing a dead lettered intent was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE action_outbox SET dead_lettered_at=NULL, attempts=attempts+1 WHERE action_ref=$1`, pendingAction.ActionRef); err == nil {
		t.Fatal("resurrecting a dead lettered intent was accepted")
	}
}
