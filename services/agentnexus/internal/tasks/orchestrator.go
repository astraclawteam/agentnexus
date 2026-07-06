package tasks

import (
	"context"
	"time"
)

type EventPublisher interface {
	PublishTaskEvent(context.Context, TaskEvent) error
}

type Orchestrator struct {
	store     Store
	publisher EventPublisher
	newID     func() string
	now       func() time.Time
}

type Option func(*Orchestrator)

func NewOrchestrator(store Store, publisher EventPublisher, opts ...Option) *Orchestrator {
	o := &Orchestrator{
		store:     store,
		publisher: publisher,
		newID:     func() string { return randomID("task") },
		now:       func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func WithIDGenerator(newID func() string) Option {
	return func(o *Orchestrator) {
		o.newID = newID
	}
}

func (o *Orchestrator) CreateTaskRun(ctx context.Context, input CreateTaskRunInput) (TaskRun, error) {
	run, err := o.store.CreateTaskRun(ctx, TaskRun{
		ID:           o.newID(),
		EnterpriseID: input.EnterpriseID,
		ActorUserID:  input.ActorUserID,
		RequestID:    input.RequestID,
		TraceID:      input.TraceID,
		Status:       TaskStatusQueued,
	})
	if err != nil {
		return TaskRun{}, err
	}

	if err := o.publish(ctx, TaskEvent{
		Subject:      SubjectTaskCreated,
		EnterpriseID: run.EnterpriseID,
		TaskRunID:    run.ID,
		Status:       run.Status,
	}); err != nil {
		return TaskRun{}, err
	}
	return run, nil
}

func (o *Orchestrator) AppendTaskStep(ctx context.Context, input AppendTaskStepInput) (TaskStep, error) {
	run, err := o.store.GetTaskRun(ctx, input.EnterpriseID, input.TaskRunID)
	if err != nil {
		return TaskStep{}, err
	}
	if isTerminal(run.Status) {
		return TaskStep{}, ErrInvalidTransition
	}

	status := input.Status
	if status == "" {
		status = TaskStatusRunning
	}
	if !isKnownStatus(status) {
		return TaskStep{}, ErrInvalidTransition
	}

	step, err := o.store.AppendTaskStep(ctx, TaskStep{
		ID:           o.newID(),
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    input.TaskRunID,
		Name:         input.Name,
		Status:       status,
		InputHash:    input.InputHash,
		OutputHash:   input.OutputHash,
	})
	if err != nil {
		return TaskStep{}, err
	}

	if status == TaskStatusRunning && run.Status != TaskStatusRunning {
		if !canTransition(run.Status, TaskStatusRunning) {
			return TaskStep{}, ErrInvalidTransition
		}
		if _, err := o.store.UpdateTaskRunStatus(ctx, input.EnterpriseID, input.TaskRunID, TaskStatusRunning); err != nil {
			return TaskStep{}, err
		}
	}

	if err := o.publish(ctx, TaskEvent{
		Subject:      SubjectTaskStep,
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    input.TaskRunID,
		TaskStepID:   step.ID,
		Status:       step.Status,
		Payload: map[string]any{
			"name": step.Name,
		},
	}); err != nil {
		return TaskStep{}, err
	}
	return step, nil
}

func (o *Orchestrator) WaitForConfirmation(ctx context.Context, input WaitForConfirmationInput) (TaskRun, error) {
	run, err := o.store.GetTaskRun(ctx, input.EnterpriseID, input.TaskRunID)
	if err != nil {
		return TaskRun{}, err
	}
	if !canTransition(run.Status, TaskStatusWaitingConfirmation) {
		return TaskRun{}, ErrInvalidTransition
	}

	run, err = o.store.UpdateTaskRunStatus(ctx, input.EnterpriseID, input.TaskRunID, TaskStatusWaitingConfirmation)
	if err != nil {
		return TaskRun{}, err
	}
	checkpoint, err := o.store.CreateConfirmationCheckpoint(ctx, ConfirmationCheckpoint{
		ID:           o.newID(),
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    input.TaskRunID,
		Status:       ConfirmationStatusPending,
		Reason:       input.Reason,
	})
	if err != nil {
		return TaskRun{}, err
	}

	if err := o.publish(ctx, TaskEvent{
		Subject:      SubjectTaskStep,
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    input.TaskRunID,
		Status:       run.Status,
		Payload: map[string]any{
			"checkpoint_id": checkpoint.ID,
			"reason":        input.Reason,
		},
	}); err != nil {
		return TaskRun{}, err
	}
	return run, nil
}

func (o *Orchestrator) CompleteTask(ctx context.Context, input CompleteTaskInput) (TaskRun, error) {
	run, err := o.store.GetTaskRun(ctx, input.EnterpriseID, input.TaskRunID)
	if err != nil {
		return TaskRun{}, err
	}
	if !isTerminal(input.Status) || !canTransition(run.Status, input.Status) {
		return TaskRun{}, ErrInvalidTransition
	}

	run, err = o.store.UpdateTaskRunStatus(ctx, input.EnterpriseID, input.TaskRunID, input.Status)
	if err != nil {
		return TaskRun{}, err
	}

	if err := o.publish(ctx, TaskEvent{
		Subject:      SubjectTaskCompleted,
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    input.TaskRunID,
		Status:       run.Status,
	}); err != nil {
		return TaskRun{}, err
	}
	return run, nil
}

func (o *Orchestrator) publish(ctx context.Context, event TaskEvent) error {
	if o.publisher == nil {
		return nil
	}
	event.OccurredAt = o.now()
	return o.publisher.PublishTaskEvent(ctx, event)
}
