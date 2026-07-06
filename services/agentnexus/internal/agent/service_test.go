package agent

import (
	"context"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

func TestServiceStartsRunAndAppendsMessageAndConfirmation(t *testing.T) {
	store := tasks.NewMemoryStore()
	service := NewService(tasks.NewOrchestrator(store, nil, tasks.WithIDGenerator(sequenceIDs("run_1", "step_plan", "step_msg", "checkpoint_1"))))

	run, err := service.StartRun(context.Background(), StartRunInput{
		EnterpriseID: "ent_1",
		ActorUserID:  "user_ada",
		RequestID:    "req_1",
		TraceID:      "trace_1",
		Goal:         "import organization preview",
	})
	if err != nil {
		t.Fatalf("StartRun returned error: %v", err)
	}
	if run.ID != "run_1" || run.Status != tasks.TaskStatusRunning {
		t.Fatalf("run = %+v, want run_1 running", run)
	}
	if !hasTool(run.Tools, ToolOrgImportPreview) || !hasTool(run.Tools, ToolConnectorInstanceSmoke) || !hasTool(run.Tools, ToolDeploymentFirstRunPlan) {
		t.Fatalf("tools = %+v, missing required internal tools", run.Tools)
	}

	message, err := service.AddMessage(context.Background(), AddMessageInput{
		EnterpriseID: "ent_1",
		RunID:        run.ID,
		Message:      "preview OA import",
	})
	if err != nil {
		t.Fatalf("AddMessage returned error: %v", err)
	}
	if message.StepID != "step_msg" || message.Status != tasks.TaskStatusRunning {
		t.Fatalf("message = %+v, want step_msg running", message)
	}

	confirmation, err := service.RequestConfirmation(context.Background(), RequestConfirmationInput{
		EnterpriseID: "ent_1",
		RunID:        run.ID,
		Reason:       "apply connector draft",
	})
	if err != nil {
		t.Fatalf("RequestConfirmation returned error: %v", err)
	}
	if confirmation.RunID != run.ID || confirmation.Status != tasks.TaskStatusWaitingConfirmation {
		t.Fatalf("confirmation = %+v, want waiting confirmation for run", confirmation)
	}
	if checkpoints := store.ConfirmationCheckpointCount(); checkpoints != 1 {
		t.Fatalf("checkpoint count = %d, want 1", checkpoints)
	}
}

func hasTool(tools []Tool, name string) bool {
	for _, tool := range tools {
		if tool.Name == name {
			return true
		}
	}
	return false
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
