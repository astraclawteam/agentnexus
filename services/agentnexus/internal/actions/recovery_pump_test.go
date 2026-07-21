package actions

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeRepublisher struct {
	mu     sync.Mutex
	calls  int
	tenant string
	errs   []error
}

func (f *fakeRepublisher) RepublishPending(_ context.Context, tenantRef string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.tenant = tenantRef
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return 0, err
	}
	return 1, nil
}

func (f *fakeRepublisher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestRecoveryPumpRejectsIncompleteConfiguration(t *testing.T) {
	if _, err := NewRecoveryPump(nil, "tenant-1", time.Second); err == nil {
		t.Fatal("a pump without a republisher must not construct")
	}
	if _, err := NewRecoveryPump(&fakeRepublisher{}, "", time.Second); err == nil {
		t.Fatal("a pump without a tenant must not construct")
	}
	if _, err := NewRecoveryPump(&fakeRepublisher{}, "tenant-1", 0); err == nil {
		t.Fatal("a pump without a positive interval must not construct")
	}
}

// TestRecoveryPumpDrainsImmediatelyOnStart is the crash-recovery property: a
// process that restarts with intents already written but unpublished must not
// wait a full interval before delivering them.
func TestRecoveryPumpDrainsImmediatelyOnStart(t *testing.T) {
	republisher := &fakeRepublisher{}
	pump, err := NewRecoveryPump(republisher, "tenant-1", time.Hour)
	if err != nil {
		t.Fatalf("new pump: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pump.Run(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for republisher.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("pump did not drain the outbox on start")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pump did not stop when its context was cancelled")
	}
	if republisher.tenant != "tenant-1" {
		t.Fatalf("pump republished for tenant %q", republisher.tenant)
	}
}

// TestRecoveryPumpSurvivesTransientFailure encodes why this loop exists at all:
// the outbox row is already committed, so a publish outage must be retried on
// the next tick rather than ending the pump and stranding the intent forever.
func TestRecoveryPumpSurvivesTransientFailure(t *testing.T) {
	republisher := &fakeRepublisher{errs: []error{errors.New("nats down"), errors.New("still down")}}
	pump, err := NewRecoveryPump(republisher, "tenant-1", 5*time.Millisecond)
	if err != nil {
		t.Fatalf("new pump: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pump.Run(ctx)

	deadline := time.After(2 * time.Second)
	for republisher.callCount() < 3 {
		select {
		case <-deadline:
			t.Fatalf("pump stopped after a transient failure; calls=%d", republisher.callCount())
		case <-time.After(5 * time.Millisecond):
		}
	}
}
