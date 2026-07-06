package tasks

import (
	"errors"
	"time"
)

type TaskStatus string

const (
	TaskStatusQueued              TaskStatus = "queued"
	TaskStatusRunning             TaskStatus = "running"
	TaskStatusWaitingConfirmation TaskStatus = "waiting_confirmation"
	TaskStatusSucceeded           TaskStatus = "succeeded"
	TaskStatusFailed              TaskStatus = "failed"
	TaskStatusCancelled           TaskStatus = "cancelled"
)

const (
	ConfirmationStatusPending  = "pending"
	ConfirmationStatusApproved = "approved"
	ConfirmationStatusRejected = "rejected"
)

const (
	SubjectTaskCreated   = "agentnexus.tasks.created"
	SubjectTaskStep      = "agentnexus.tasks.step"
	SubjectTaskCompleted = "agentnexus.tasks.completed"
)

var (
	ErrTaskNotFound      = errors.New("task not found")
	ErrInvalidTransition = errors.New("invalid task status transition")
)

type TaskRun struct {
	ID           string
	EnterpriseID string
	ActorUserID  string
	RequestID    string
	TraceID      string
	Status       TaskStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type TaskStep struct {
	ID           string
	EnterpriseID string
	TaskRunID    string
	Name         string
	Status       TaskStatus
	InputHash    string
	OutputHash   string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ConfirmationCheckpoint struct {
	ID           string
	EnterpriseID string
	TaskRunID    string
	TaskStepID   string
	Status       string
	Reason       string
	CreatedAt    time.Time
	ResolvedAt   *time.Time
}

type TaskEvent struct {
	Subject      string         `json:"subject"`
	EnterpriseID string         `json:"enterprise_id"`
	TaskRunID    string         `json:"task_run_id"`
	TaskStepID   string         `json:"task_step_id,omitempty"`
	Status       TaskStatus     `json:"status"`
	Payload      map[string]any `json:"payload,omitempty"`
	OccurredAt   time.Time      `json:"occurred_at"`
}

type CreateTaskRunInput struct {
	EnterpriseID string
	ActorUserID  string
	RequestID    string
	TraceID      string
}

type AppendTaskStepInput struct {
	EnterpriseID string
	TaskRunID    string
	Name         string
	Status       TaskStatus
	InputHash    string
	OutputHash   string
}

type WaitForConfirmationInput struct {
	EnterpriseID string
	TaskRunID    string
	Reason       string
}

type CompleteTaskInput struct {
	EnterpriseID string
	TaskRunID    string
	Status       TaskStatus
}

func isTerminal(status TaskStatus) bool {
	return status == TaskStatusSucceeded || status == TaskStatusFailed || status == TaskStatusCancelled
}

func isKnownStatus(status TaskStatus) bool {
	switch status {
	case TaskStatusQueued, TaskStatusRunning, TaskStatusWaitingConfirmation, TaskStatusSucceeded, TaskStatusFailed, TaskStatusCancelled:
		return true
	default:
		return false
	}
}

func canTransition(from, to TaskStatus) bool {
	if !isKnownStatus(from) || !isKnownStatus(to) || from == to {
		return false
	}
	if isTerminal(from) {
		return false
	}
	switch to {
	case TaskStatusRunning:
		return from == TaskStatusQueued || from == TaskStatusWaitingConfirmation
	case TaskStatusWaitingConfirmation:
		return from == TaskStatusRunning
	case TaskStatusSucceeded, TaskStatusFailed, TaskStatusCancelled:
		return from == TaskStatusQueued || from == TaskStatusRunning || from == TaskStatusWaitingConfirmation
	default:
		return false
	}
}
