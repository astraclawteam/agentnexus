package tasks

import (
	"context"
	"errors"
	"testing"
)

func TestOrchestratorTaskLifecycle(t *testing.T) {
	ctx := context.Background()
	publisher := &recordingPublisher{}
	store := NewMemoryStore()
	orchestrator := NewOrchestrator(
		store,
		publisher,
		WithIDGenerator(sequenceIDs("task_1", "step_1", "checkpoint_1")),
	)

	run, err := orchestrator.CreateTaskRun(ctx, CreateTaskRunInput{
		EnterpriseID: "ent_1",
		ActorUserID:  "user_1",
		RequestID:    "req_1",
		TraceID:      "trace_1",
	})
	if err != nil {
		t.Fatalf("CreateTaskRun returned error: %v", err)
	}
	if run.Status != TaskStatusQueued {
		t.Fatalf("status = %q, want %q", run.Status, TaskStatusQueued)
	}
	assertLastSubject(t, publisher, SubjectTaskCreated)

	step, err := orchestrator.AppendTaskStep(ctx, AppendTaskStepInput{
		EnterpriseID: "ent_1",
		TaskRunID:    run.ID,
		Name:         "collect_context",
		Status:       TaskStatusRunning,
		InputHash:    "sha256:in",
		OutputHash:   "sha256:out",
	})
	if err != nil {
		t.Fatalf("AppendTaskStep returned error: %v", err)
	}
	if step.Status != TaskStatusRunning {
		t.Fatalf("step status = %q, want %q", step.Status, TaskStatusRunning)
	}
	assertLastSubject(t, publisher, SubjectTaskStep)

	run, err = orchestrator.WaitForConfirmation(ctx, WaitForConfirmationInput{
		EnterpriseID: "ent_1",
		TaskRunID:    run.ID,
		Reason:       "external approval required",
	})
	if err != nil {
		t.Fatalf("WaitForConfirmation returned error: %v", err)
	}
	if run.Status != TaskStatusWaitingConfirmation {
		t.Fatalf("status = %q, want %q", run.Status, TaskStatusWaitingConfirmation)
	}
	if got := store.ConfirmationCheckpointCount(); got != 1 {
		t.Fatalf("confirmation checkpoint count = %d, want 1", got)
	}
	assertLastSubject(t, publisher, SubjectTaskStep)

	run, err = orchestrator.CompleteTask(ctx, CompleteTaskInput{
		EnterpriseID: "ent_1",
		TaskRunID:    run.ID,
		Status:       TaskStatusSucceeded,
	})
	if err != nil {
		t.Fatalf("CompleteTask returned error: %v", err)
	}
	if run.Status != TaskStatusSucceeded {
		t.Fatalf("status = %q, want %q", run.Status, TaskStatusSucceeded)
	}
	assertLastSubject(t, publisher, SubjectTaskCompleted)
}

func TestOrchestratorRejectsInvalidTransitions(t *testing.T) {
	ctx := context.Background()
	orchestrator := NewOrchestrator(
		NewMemoryStore(),
		&recordingPublisher{},
		WithIDGenerator(sequenceIDs("task_1", "step_1")),
	)

	run, err := orchestrator.CreateTaskRun(ctx, CreateTaskRunInput{
		EnterpriseID: "ent_1",
		ActorUserID:  "user_1",
		RequestID:    "req_1",
	})
	if err != nil {
		t.Fatalf("CreateTaskRun returned error: %v", err)
	}

	if _, err := orchestrator.WaitForConfirmation(ctx, WaitForConfirmationInput{
		EnterpriseID: "ent_1",
		TaskRunID:    run.ID,
		Reason:       "too early",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("WaitForConfirmation error = %v, want ErrInvalidTransition", err)
	}

	if _, err := orchestrator.CompleteTask(ctx, CompleteTaskInput{
		EnterpriseID: "ent_1",
		TaskRunID:    run.ID,
		Status:       TaskStatusSucceeded,
	}); err != nil {
		t.Fatalf("CompleteTask returned error: %v", err)
	}

	if _, err := orchestrator.AppendTaskStep(ctx, AppendTaskStepInput{
		EnterpriseID: "ent_1",
		TaskRunID:    run.ID,
		Name:         "after_terminal",
		Status:       TaskStatusRunning,
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("AppendTaskStep error = %v, want ErrInvalidTransition", err)
	}
}

type recordingPublisher struct {
	events []TaskEvent
}

func (p *recordingPublisher) PublishTaskEvent(_ context.Context, event TaskEvent) error {
	p.events = append(p.events, event)
	return nil
}

func assertLastSubject(t *testing.T, publisher *recordingPublisher, want string) {
	t.Helper()
	if len(publisher.events) == 0 {
		t.Fatal("no events were published")
	}
	if got := publisher.events[len(publisher.events)-1].Subject; got != want {
		t.Fatalf("last subject = %q, want %q", got, want)
	}
}

func sequenceIDs(ids ...string) func() string {
	index := 0
	return func() string {
		if index >= len(ids) {
			return "extra_id"
		}
		id := ids[index]
		index++
		return id
	}
}
