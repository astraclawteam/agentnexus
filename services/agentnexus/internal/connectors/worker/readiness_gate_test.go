package worker

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingSource struct {
	mu     sync.Mutex
	ancels int
}

func (s *recordingSource) Fetch(context.Context, int, time.Duration) ([]Delivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ancels++
	return nil, nil
}

func (s *recordingSource) fetches() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ancels
}

type scriptedRunner struct {
	mu         sync.Mutex
	readyAfter int
	checks     int
	ran        bool
}

func (r *scriptedRunner) CheckReady(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.checks++
	if r.readyAfter < 0 || r.checks < r.readyAfter {
		return errors.Join(ErrNotReady, errors.New("seam missing"))
	}
	return nil
}

func (r *scriptedRunner) Run(ctx context.Context, source DispatchSource) error {
	r.mu.Lock()
	r.ran = true
	r.mu.Unlock()
	_, _ = source.Fetch(ctx, 1, time.Millisecond)
	<-ctx.Done()
	return ctx.Err()
}

func (r *scriptedRunner) didRun() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ran
}

func (r *scriptedRunner) checkCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checks
}

// TestRunWhenReadyNeverConsumesWhileNotReady is the whole point of the gate.
// Worker.Run fetches immediately; it does not check readiness itself. A worker
// whose binding resolver, receipt signer or observation producer is missing
// would therefore pull real dispatch intents off the stream and fail every one
// of them, turning a deployment gap into redelivery churn against durable
// Actions. Nothing may touch the stream until CheckReady returns nil.
func TestRunWhenReadyNeverConsumesWhileNotReady(t *testing.T) {
	runner := &scriptedRunner{readyAfter: -1} // never ready
	source := &recordingSource{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- RunWhenReady(ctx, runner, source, time.Millisecond) }()

	deadline := time.After(2 * time.Second)
	for runner.checkCount() < 3 {
		select {
		case <-deadline:
			t.Fatalf("gate stopped probing readiness; checks=%d", runner.checkCount())
		case <-time.After(time.Millisecond):
		}
	}
	if source.fetches() != 0 {
		t.Fatalf("a not-ready worker consumed %d dispatch batch(es)", source.fetches())
	}
	if runner.didRun() {
		t.Fatal("a not-ready worker entered its run loop")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gate did not stop when its context was cancelled")
	}
}

// TestRunWhenReadyStartsOnceReady covers the other half: the gate must not be a
// permanent block. A deployment that wires its seams while the process is up
// starts serving without a restart.
func TestRunWhenReadyStartsOnceReady(t *testing.T) {
	runner := &scriptedRunner{readyAfter: 3}
	source := &recordingSource{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- RunWhenReady(ctx, runner, source, time.Millisecond) }()

	deadline := time.After(2 * time.Second)
	for !runner.didRun() {
		select {
		case <-deadline:
			t.Fatalf("gate never started the worker; checks=%d", runner.checkCount())
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gate did not return after the run loop stopped")
	}
}

func TestRunWhenReadyRejectsIncompleteArguments(t *testing.T) {
	ctx := context.Background()
	if err := RunWhenReady(ctx, nil, &recordingSource{}, time.Second); err == nil {
		t.Fatal("gate without a runner must fail")
	}
	if err := RunWhenReady(ctx, &scriptedRunner{}, nil, time.Second); err == nil {
		t.Fatal("gate without a dispatch source must fail")
	}
	if err := RunWhenReady(ctx, &scriptedRunner{}, &recordingSource{}, 0); err == nil {
		t.Fatal("gate without a positive poll interval must fail")
	}
}
