package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

const (
	ToolOrgImportPreview         = "org_import_preview"
	ToolConnectorPackageValidate = "connector_package_validate"
	ToolConnectorInstanceSmoke   = "connector_instance_smoke"
	ToolDeploymentFirstRunPlan   = "deployment_first_run_plan"
	ToolAuditAppend              = "audit_append"
	ToolConfirmationWait         = "confirmation_wait"
)

type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Service struct {
	orchestrator *tasks.Orchestrator
}

func NewService(orchestrator *tasks.Orchestrator) *Service {
	if orchestrator == nil {
		orchestrator = tasks.NewOrchestrator(tasks.NewMemoryStore(), nil)
	}
	return &Service{orchestrator: orchestrator}
}

type StartRunInput struct {
	EnterpriseID string
	ActorUserID  string
	RequestID    string
	TraceID      string
	Goal         string
}

type Run struct {
	ID     string
	Status tasks.TaskStatus
	Tools  []Tool
}

type AddMessageInput struct {
	EnterpriseID string
	RunID        string
	Message      string
}

type MessageResult struct {
	RunID  string
	StepID string
	Status tasks.TaskStatus
}

type RequestConfirmationInput struct {
	EnterpriseID string
	RunID        string
	Reason       string
}

type ConfirmationResult struct {
	RunID  string
	Status tasks.TaskStatus
}

func (s *Service) StartRun(ctx context.Context, input StartRunInput) (Run, error) {
	if input.EnterpriseID == "" || input.ActorUserID == "" || input.RequestID == "" {
		return Run{}, fmt.Errorf("enterprise_id, actor_user_id, and request_id are required")
	}
	run, err := s.orchestrator.CreateTaskRun(ctx, tasks.CreateTaskRunInput{
		EnterpriseID: input.EnterpriseID,
		ActorUserID:  input.ActorUserID,
		RequestID:    input.RequestID,
		TraceID:      input.TraceID,
	})
	if err != nil {
		return Run{}, err
	}
	if _, err := s.orchestrator.AppendTaskStep(ctx, tasks.AppendTaskStepInput{
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    run.ID,
		Name:         "agent_tool_plan",
		Status:       tasks.TaskStatusRunning,
		InputHash:    hashValue(input.Goal),
		OutputHash:   hashValue(DefaultTools()),
	}); err != nil {
		return Run{}, err
	}
	return Run{ID: run.ID, Status: tasks.TaskStatusRunning, Tools: DefaultTools()}, nil
}

func (s *Service) AddMessage(ctx context.Context, input AddMessageInput) (MessageResult, error) {
	if input.EnterpriseID == "" || input.RunID == "" || input.Message == "" {
		return MessageResult{}, fmt.Errorf("enterprise_id, run_id, and message are required")
	}
	step, err := s.orchestrator.AppendTaskStep(ctx, tasks.AppendTaskStepInput{
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    input.RunID,
		Name:         "agent_message_received",
		Status:       tasks.TaskStatusRunning,
		InputHash:    hashValue(input.Message),
	})
	if err != nil {
		return MessageResult{}, err
	}
	return MessageResult{RunID: input.RunID, StepID: step.ID, Status: step.Status}, nil
}

func (s *Service) RequestConfirmation(ctx context.Context, input RequestConfirmationInput) (ConfirmationResult, error) {
	if input.EnterpriseID == "" || input.RunID == "" || input.Reason == "" {
		return ConfirmationResult{}, fmt.Errorf("enterprise_id, run_id, and reason are required")
	}
	run, err := s.orchestrator.WaitForConfirmation(ctx, tasks.WaitForConfirmationInput{
		EnterpriseID: input.EnterpriseID,
		TaskRunID:    input.RunID,
		Reason:       input.Reason,
	})
	if err != nil {
		return ConfirmationResult{}, err
	}
	return ConfirmationResult{RunID: input.RunID, Status: run.Status}, nil
}

func DefaultTools() []Tool {
	return []Tool{
		{Name: ToolOrgImportPreview, Description: "Preview an OA organization import without persistence."},
		{Name: ToolConnectorPackageValidate, Description: "Validate an open-core connector manifest."},
		{Name: ToolConnectorInstanceSmoke, Description: "Run a connector instance read smoke check."},
		{Name: ToolDeploymentFirstRunPlan, Description: "Build the private-dev first deployment dry-run plan."},
		{Name: ToolAuditAppend, Description: "Append runtime or tool-call audit evidence."},
		{Name: ToolConfirmationWait, Description: "Pause a run until a human confirmation checkpoint is resolved."},
	}
}

func hashValue(value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
