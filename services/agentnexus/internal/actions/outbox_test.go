package actions

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// outboxClock is a hand-advanced clock. The backoff and give-up behaviour of
// the drain is defined in terms of time, so these tests move time explicitly
// instead of sleeping through it.
type outboxClock struct {
	mu sync.Mutex
	at time.Time
}

func newOutboxClock() *outboxClock {
	return &outboxClock{at: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *outboxClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *outboxClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// scriptedPublisher records every published intent and fails the ones a test
// tells it to. reject selects the dispatch refs (by action ref) that cannot be
// delivered; nil means everything succeeds.
type scriptedPublisher struct {
	mu      sync.Mutex
	sent    []DispatchMessage
	calls   []DispatchMessage
	reject  func(DispatchMessage) bool
	latency time.Duration
}

func (p *scriptedPublisher) PublishDispatch(_ context.Context, message DispatchMessage) error {
	p.mu.Lock()
	p.calls = append(p.calls, message)
	reject := p.reject
	latency := p.latency
	p.mu.Unlock()
	if latency > 0 {
		time.Sleep(latency)
	}
	if reject != nil && reject(message) {
		return errors.New("transport rejected the intent")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, message)
	return nil
}

// published returns the intents the transport ACCEPTED.
func (p *scriptedPublisher) published() []DispatchMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]DispatchMessage(nil), p.sent...)
}

// attempted returns every intent the publisher was ASKED to deliver, accepted
// or not. The difference between this and published() is what the retry
// accounting has to get right.
func (p *scriptedPublisher) attempted() []DispatchMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]DispatchMessage(nil), p.calls...)
}

// outboxFixture is a service over a MemoryStore with a hand-advanced clock.
type outboxFixture struct {
	t         *testing.T
	svc       *Service
	store     *MemoryStore
	audit     *MemoryAuditSink
	clock     *outboxClock
	publisher *scriptedPublisher
	principal runtime.PrincipalContext
	requests  int
}

func newOutboxFixture(t *testing.T, opts ...Option) *outboxFixture {
	t.Helper()
	clock := newOutboxClock()
	publisher := &scriptedPublisher{}
	store := NewMemoryStore()
	audit := NewMemoryAuditSink()
	base := []Option{
		WithIDGenerator(sequentialIDs()),
		WithReceiptVerifier(&fakeReceiptVerifier{}),
		WithClock(clock.now),
		WithPublisher(publisher),
	}
	svc, err := NewService(store, audit, append(base, opts...)...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return &outboxFixture{t: t, svc: svc, store: store, audit: audit, clock: clock, publisher: publisher, principal: testPrincipal(runtime.TrustFirstParty)}
}

// serviceOver builds a SECOND service over the same durable store — the way a
// replica, or a restarted process, sees the outbox another one wrote.
func (f *outboxFixture) serviceOver(publisher Publisher) *Service {
	f.t.Helper()
	opts := []Option{WithIDGenerator(sequentialIDs()), WithReceiptVerifier(&fakeReceiptVerifier{}), WithClock(f.clock.now)}
	if publisher != nil {
		opts = append(opts, WithPublisher(publisher))
	}
	svc, err := NewService(f.store, f.audit, opts...)
	if err != nil {
		f.t.Fatalf("NewService: %v", err)
	}
	return svc
}

// dispatch drives one fresh action from request through grant to dispatched and
// returns it. Each call uses a distinct idempotency key, so a test can queue
// several independent intents.
func (f *outboxFixture) dispatch(svc *Service) Action {
	f.t.Helper()
	ctx := context.Background()
	f.requests++
	req := testRequest(f.t)
	req.IdempotencyKey = fmt.Sprintf("idem-outbox-%08d", f.requests)
	action, err := svc.RequestAction(ctx, f.principal, req)
	if err != nil {
		f.t.Fatalf("RequestAction: %v", err)
	}
	if _, err := svc.Grant(ctx, f.principal, action.ActionRef); err != nil {
		f.t.Fatalf("Grant: %v", err)
	}
	dispatched, err := svc.Dispatch(ctx, f.principal, action.ActionRef)
	if err != nil {
		f.t.Fatalf("Dispatch: %v", err)
	}
	// Distinct creation instants keep the oldest-first drain order well defined.
	f.clock.advance(time.Millisecond)
	return dispatched
}

func (f *outboxFixture) pending() []Dispatch {
	f.t.Helper()
	pending, err := f.store.PendingDispatches(context.Background(), f.principal.TenantRef, 0)
	if err != nil {
		f.t.Fatalf("PendingDispatches: %v", err)
	}
	return pending
}

func (f *outboxFixture) deadLettered() []Dispatch {
	f.t.Helper()
	dead, err := f.store.DeadLetteredDispatches(context.Background(), f.principal.TenantRef, 0)
	if err != nil {
		f.t.Fatalf("DeadLetteredDispatches: %v", err)
	}
	return dead
}

// ---------------------------------------------------------------------------
// Defect 1: Dispatch publishes; the pump is recovery, not delivery
// ---------------------------------------------------------------------------

// TestActionDispatchPublishesWithoutWaitingForTheRecoveryPump is the whole
// point of the outbox: a dispatched action must reach the transport as part of
// dispatching it. Committing the durable intent and never publishing it made
// the recovery pump the only delivery path, so every dispatch silently
// inherited the pump's interval as its latency.
func TestActionDispatchPublishesWithoutWaitingForTheRecoveryPump(t *testing.T) {
	f := newOutboxFixture(t)
	action := f.dispatch(f.svc)

	sent := f.publisher.published()
	if len(sent) != 1 {
		t.Fatalf("published %d intents during dispatch, want exactly 1 (no pump ran)", len(sent))
	}
	if sent[0].ActionRef != action.ActionRef || sent[0].GrantRef != action.GrantRef {
		t.Fatalf("published intent %+v does not bind the dispatched action %s/%s", sent[0], action.ActionRef, action.GrantRef)
	}
	if pending := f.pending(); len(pending) != 0 {
		t.Fatalf("pending after a successful dispatch = %d, want 0 (the intent was delivered and stamped)", len(pending))
	}
	// The pump is now genuinely idle: there is nothing left for it to recover.
	published, err := f.svc.RepublishPending(context.Background(), f.principal.TenantRef)
	if err != nil || published != 0 {
		t.Fatalf("RepublishPending after a delivered dispatch = %d err=%v, want 0", published, err)
	}
	if len(f.publisher.published()) != 1 {
		t.Fatalf("the pump republished a delivered intent; published = %+v", f.publisher.published())
	}
}

// TestActionDispatchSurvivesAPublishFailure pins the other half: the action IS
// dispatched (the one-use grant is consumed, the row is durable), so a
// transport outage must not fail the call and invite a blind re-dispatch. The
// intent stays pending for the pump instead.
func TestActionDispatchSurvivesAPublishFailure(t *testing.T) {
	f := newOutboxFixture(t)
	f.publisher.reject = func(DispatchMessage) bool { return true }
	action := f.dispatch(f.svc)

	if action.Status != StatusDispatched {
		t.Fatalf("status = %q, want dispatched even though the publish failed", action.Status)
	}
	pending := f.pending()
	if len(pending) != 1 {
		t.Fatalf("pending after a failed publish = %d, want 1", len(pending))
	}
	if pending[0].Attempts != 1 {
		t.Fatalf("attempts after one failed publish = %d, want 1", pending[0].Attempts)
	}
	if pending[0].LastError == "" {
		t.Fatal("a failed attempt recorded no reason")
	}
	if !pending[0].NextAttemptAt.After(f.clock.now()) {
		t.Fatalf("next attempt %v is not in the future (clock %v); the drain would spin on it", pending[0].NextAttemptAt, f.clock.now())
	}
	// A blind re-dispatch is still refused — the recovery path is the pump.
	if _, err := f.svc.Dispatch(context.Background(), f.principal, action.ActionRef); !errors.Is(err, ErrBlindRetryForbidden) {
		t.Fatalf("re-dispatch after a failed publish err = %v, want ErrBlindRetryForbidden", err)
	}
}

// ---------------------------------------------------------------------------
// At-least-once: the crash AFTER the broker accepted the intent
// ---------------------------------------------------------------------------

// crashingClaimStore simulates the window the "double dispatch is impossible by
// construction" claim used to deny: the transport ACCEPTS the intent and the
// process dies before the published stamp is written. The claim and the publish
// really happen; the outcome is simply never applied, leaving the row exactly
// as it was.
type crashingClaimStore struct {
	*MemoryStore
	mu    sync.Mutex
	crash bool
}

func (s *crashingClaimStore) setCrash(crash bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crash = crash
}

func (s *crashingClaimStore) crashing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.crash
}

func (s *crashingClaimStore) ClaimDispatch(ctx context.Context, tenantRef, dispatchRef string, at time.Time, deliver DispatchDeliverer) (bool, error) {
	if !s.crashing() {
		return s.MemoryStore.ClaimDispatch(ctx, tenantRef, dispatchRef, at, deliver)
	}
	pending, err := s.MemoryStore.PendingDispatches(ctx, tenantRef, 0)
	if err != nil {
		return false, err
	}
	for _, dispatch := range pending {
		if dispatch.DispatchRef == dispatchRef {
			deliver(ctx, dispatch) // accepted by the transport...
			return true, nil       // ...and then nothing was ever stamped.
		}
	}
	return false, nil
}

// TestActionOutboxRepublishesIdenticalIntentAfterAPublishedButUnstampedCrash is
// the crash the existing tests never covered: they only simulated dying BEFORE
// the publish. Dying AFTER it is the case that makes the outbox at-least-once
// rather than exactly-once, and the property that has to hold is not "it never
// happens" but "the redelivery is byte-identical and carries the same dedup
// id", because that is what the connector's inbox deduplicates on.
func TestActionOutboxRepublishesIdenticalIntentAfterAPublishedButUnstampedCrash(t *testing.T) {
	f := newOutboxFixture(t)
	crashing := &crashingClaimStore{MemoryStore: f.store}
	svc, err := NewService(crashing, f.audit, WithIDGenerator(sequentialIDs()), WithReceiptVerifier(&fakeReceiptVerifier{}), WithClock(f.clock.now), WithPublisher(f.publisher))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	crashing.setCrash(true)
	action := f.dispatch(svc)

	first := f.publisher.published()
	if len(first) != 1 {
		t.Fatalf("published %d intents before the crash, want 1", len(first))
	}
	if pending := f.pending(); len(pending) != 1 {
		t.Fatalf("pending after the unstamped publish = %d, want 1 (the stamp never committed)", len(pending))
	}

	// The process restarts and its pump drains what it finds.
	crashing.setCrash(false)
	published, err := svc.RepublishPending(context.Background(), f.principal.TenantRef)
	if err != nil || published != 1 {
		t.Fatalf("RepublishPending = %d err=%v, want 1", published, err)
	}

	sent := f.publisher.published()
	if len(sent) != 2 {
		t.Fatalf("published %d intents in total, want 2 (the duplicate this window makes unavoidable)", len(sent))
	}
	if sent[0] != sent[1] {
		t.Fatalf("the redelivery is not identical to the first publish:\n first=%+v\nsecond=%+v", sent[0], sent[1])
	}
	if sent[1].DispatchRef == "" || sent[1].DispatchRef != sent[0].DispatchRef {
		t.Fatalf("the redelivery carries no stable dedup id: %q vs %q", sent[0].DispatchRef, sent[1].DispatchRef)
	}
	if sent[1].ActionRef != action.ActionRef {
		t.Fatalf("redelivered intent binds %s, want %s", sent[1].ActionRef, action.ActionRef)
	}
	if pending := f.pending(); len(pending) != 0 {
		t.Fatalf("pending after recovery = %d, want 0", len(pending))
	}
}

// ---------------------------------------------------------------------------
// Defect 2: concurrent drains must divide the outbox, not duplicate it
// ---------------------------------------------------------------------------

// TestActionOutboxConcurrentPumpsPublishEachIntentExactlyOnce is the N-replica
// property. Every gateway replica runs its own recovery pump; a drain that only
// SELECTs pending rows has each replica read and publish the whole backlog on
// every cycle. Claiming each row for the duration of its publish is what makes
// two concurrent pumps split the work instead of doubling it.
func TestActionOutboxConcurrentPumpsPublishEachIntentExactlyOnce(t *testing.T) {
	f := newOutboxFixture(t)
	// Dispatch with no publisher wired, so the whole backlog is left for the
	// pumps rather than delivered inline.
	crashed := f.serviceOver(nil)
	const intents = 24
	for i := 0; i < intents; i++ {
		f.dispatch(crashed)
	}
	if pending := f.pending(); len(pending) != intents {
		t.Fatalf("backlog = %d, want %d", len(pending), intents)
	}

	// A little transport latency keeps the two pumps genuinely overlapping.
	f.publisher.latency = time.Millisecond
	pumpA := f.serviceOver(f.publisher)
	pumpB := f.serviceOver(f.publisher)

	var wg sync.WaitGroup
	counts := make([]int, 2)
	errs := make([]error, 2)
	for i, pump := range []*Service{pumpA, pumpB} {
		wg.Add(1)
		go func(i int, pump *Service) {
			defer wg.Done()
			counts[i], errs[i] = pump.RepublishPending(context.Background(), f.principal.TenantRef)
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
	sent := f.publisher.attempted()
	if len(sent) != intents {
		t.Fatalf("the transport saw %d deliveries, want %d — concurrent pumps duplicated the backlog", len(sent), intents)
	}
	seen := map[string]int{}
	for _, message := range sent {
		seen[message.DispatchRef]++
	}
	for ref, count := range seen {
		if count != 1 {
			t.Fatalf("dispatch %s was published %d times by concurrent pumps", ref, count)
		}
	}
	if len(seen) != intents {
		t.Fatalf("published %d distinct intents, want %d", len(seen), intents)
	}
	if pending := f.pending(); len(pending) != 0 {
		t.Fatalf("pending after both drains = %d, want 0", len(pending))
	}
}

// ---------------------------------------------------------------------------
// Defect 3: one bad intent must not hold the queue, and must eventually stop
// ---------------------------------------------------------------------------

// TestActionOutboxUndeliverableIntentDoesNotBlockTheIntentsBehindIt is the
// head-of-line property. The drain reads oldest-first; aborting the pass on the
// first publish error meant a single permanently-unpublishable intent stopped
// every later dispatch from EVER being delivered, on every cycle, forever.
func TestActionOutboxUndeliverableIntentDoesNotBlockTheIntentsBehindIt(t *testing.T) {
	f := newOutboxFixture(t)
	crashed := f.serviceOver(nil)
	poisoned := f.dispatch(crashed)
	second := f.dispatch(crashed)
	third := f.dispatch(crashed)

	// The OLDEST intent is the one that cannot be delivered.
	f.publisher.reject = func(message DispatchMessage) bool { return message.ActionRef == poisoned.ActionRef }
	pump := f.serviceOver(f.publisher)

	published, err := pump.RepublishPending(context.Background(), f.principal.TenantRef)
	if err != nil {
		t.Fatalf("RepublishPending: %v", err)
	}
	if published != 2 {
		t.Fatalf("drain published %d intents, want 2 — the undeliverable head must not strand the rest", published)
	}
	delivered := map[string]bool{}
	for _, message := range f.publisher.published() {
		delivered[message.ActionRef] = true
	}
	for _, action := range []Action{second, third} {
		if !delivered[action.ActionRef] {
			t.Fatalf("intent %s queued behind the undeliverable one was never delivered", action.ActionRef)
		}
	}
	if delivered[poisoned.ActionRef] {
		t.Fatal("the undeliverable intent was reported delivered")
	}
	pending := f.pending()
	if len(pending) != 1 || pending[0].ActionRef != poisoned.ActionRef {
		t.Fatalf("pending after the drain = %+v, want only the undeliverable intent", pending)
	}
	if pending[0].Attempts != 1 {
		t.Fatalf("attempts on the undeliverable intent = %d, want 1", pending[0].Attempts)
	}
}

// TestActionOutboxBacksOffBeforeRetryingAFailedIntent pins that a failed intent
// is not hammered on every tick: the drain skips it until its scheduled next
// attempt. Without this, `attempts` grows once per pump interval and the
// give-up bound is reached in minutes of transport flap rather than after a
// real retry schedule.
func TestActionOutboxBacksOffBeforeRetryingAFailedIntent(t *testing.T) {
	f := newOutboxFixture(t)
	f.publisher.reject = func(DispatchMessage) bool { return true }
	f.dispatch(f.svc)

	if attempted := len(f.publisher.attempted()); attempted != 1 {
		t.Fatalf("delivery attempts after dispatch = %d, want 1", attempted)
	}
	scheduled := f.pending()[0].NextAttemptAt

	// A drain BEFORE the backoff expires must not touch the transport at all.
	if _, err := f.svc.RepublishPending(context.Background(), f.principal.TenantRef); err != nil {
		t.Fatalf("RepublishPending: %v", err)
	}
	if attempted := len(f.publisher.attempted()); attempted != 1 {
		t.Fatalf("delivery attempts during the backoff = %d, want 1 (the intent is not eligible yet)", attempted)
	}
	if got := f.pending()[0].Attempts; got != 1 {
		t.Fatalf("attempts during the backoff = %d, want 1", got)
	}

	// Once the schedule is reached the intent is eligible again.
	f.clock.advance(scheduled.Sub(f.clock.now()) + time.Second)
	if _, err := f.svc.RepublishPending(context.Background(), f.principal.TenantRef); err != nil {
		t.Fatalf("RepublishPending: %v", err)
	}
	if attempted := len(f.publisher.attempted()); attempted != 2 {
		t.Fatalf("delivery attempts after the backoff = %d, want 2", attempted)
	}
	if got := f.pending()[0].Attempts; got != 2 {
		t.Fatalf("attempts after the second failure = %d, want 2 — the column must count ATTEMPTS, not publishes", got)
	}
}

// TestActionOutboxGivesUpAndDeadLettersAfterTheAttemptBound is the give-up
// property. attempts existed but was only ever raised by the SUCCESS statement
// and nothing read it, so no retry could ever be accounted for and no intent
// could ever be abandoned. A permanently undeliverable intent must stop being
// retried and stay visible as undelivered evidence — never silently dropped and
// never silently cycling.
func TestActionOutboxGivesUpAndDeadLettersAfterTheAttemptBound(t *testing.T) {
	f := newOutboxFixture(t)
	f.publisher.reject = func(DispatchMessage) bool { return true }
	action := f.dispatch(f.svc) // attempt 1, inline at dispatch

	ctx := context.Background()
	for attempt := 2; attempt <= maxDispatchAttempts; attempt++ {
		pending := f.pending()
		if len(pending) != 1 {
			t.Fatalf("before attempt %d the intent is not pending: %+v", attempt, pending)
		}
		if pending[0].Attempts != attempt-1 {
			t.Fatalf("attempts before attempt %d = %d, want %d", attempt, pending[0].Attempts, attempt-1)
		}
		f.clock.advance(pending[0].NextAttemptAt.Sub(f.clock.now()) + time.Second)
		published, err := f.svc.RepublishPending(ctx, f.principal.TenantRef)
		if err != nil || published != 0 {
			t.Fatalf("drain %d = %d err=%v, want 0 published and no error", attempt, published, err)
		}
	}

	if attempted := len(f.publisher.attempted()); attempted != maxDispatchAttempts {
		t.Fatalf("delivery attempts = %d, want %d", attempted, maxDispatchAttempts)
	}
	if pending := f.pending(); len(pending) != 0 {
		t.Fatalf("pending after the attempt bound = %+v, want none (the drain gave up)", pending)
	}
	dead := f.deadLettered()
	if len(dead) != 1 {
		t.Fatalf("dead lettered = %d, want 1 — an abandoned intent must stay visible", len(dead))
	}
	if dead[0].ActionRef != action.ActionRef {
		t.Fatalf("dead lettered intent binds %s, want %s", dead[0].ActionRef, action.ActionRef)
	}
	if dead[0].Attempts != maxDispatchAttempts {
		t.Fatalf("dead lettered attempts = %d, want %d", dead[0].Attempts, maxDispatchAttempts)
	}
	if dead[0].LastError == "" {
		t.Fatal("the dead lettered intent records no reason")
	}
	if dead[0].Published {
		t.Fatal("a dead lettered intent must never be marked published")
	}

	// And it is never claimed again, however far the clock moves.
	f.clock.advance(24 * time.Hour)
	published, err := f.svc.RepublishPending(ctx, f.principal.TenantRef)
	if err != nil || published != 0 {
		t.Fatalf("drain after dead lettering = %d err=%v, want 0", published, err)
	}
	if attempted := len(f.publisher.attempted()); attempted != maxDispatchAttempts {
		t.Fatalf("the drain retried a dead lettered intent; attempts = %d, want %d", attempted, maxDispatchAttempts)
	}
}

// TestDispatchRetryDelayIsBoundedAndMonotonic pins the retry schedule itself:
// it must grow (so a flapping transport is not hammered) and it must stop
// growing (so recovery after a long outage stays bounded).
func TestDispatchRetryDelayIsBoundedAndMonotonic(t *testing.T) {
	previous := time.Duration(0)
	for attempt := 1; attempt <= maxDispatchAttempts; attempt++ {
		delay := dispatchRetryDelay(attempt)
		if delay < previous {
			t.Fatalf("delay for attempt %d (%v) is shorter than for attempt %d (%v)", attempt, delay, attempt-1, previous)
		}
		if delay < dispatchRetryBaseDelay || delay > dispatchRetryMaxDelay {
			t.Fatalf("delay for attempt %d = %v, want within [%v, %v]", attempt, delay, dispatchRetryBaseDelay, dispatchRetryMaxDelay)
		}
		previous = delay
	}
	if got := dispatchRetryDelay(0); got != dispatchRetryBaseDelay {
		t.Fatalf("delay for a zero attempt count = %v, want the base delay %v", got, dispatchRetryBaseDelay)
	}
	if got := dispatchRetryDelay(1000); got != dispatchRetryMaxDelay {
		t.Fatalf("delay for a very high attempt count = %v, want the cap %v", got, dispatchRetryMaxDelay)
	}
}
