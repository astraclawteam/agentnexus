package app

import (
	"context"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

func TestBuildOrgImportPreviewForTaskRequestsConfirmationOnConflicts(t *testing.T) {
	waiter := &recordingConfirmationWaiter{}
	provider := orgsource.NewMockWeComProvider(orgsource.Snapshot{
		Departments: []orgsource.Department{{ID: "dept_legal", Name: "Legal"}},
		Employees: []orgsource.Employee{
			{ID: "user_1", Email: "same@example.com", DepartmentIDs: []string{"dept_legal"}},
			{ID: "user_2", Email: "same@example.com", DepartmentIDs: []string{"dept_legal"}},
		},
	})

	preview, err := BuildOrgImportPreviewForTask(context.Background(), provider, waiter, OrgImportTaskContext{
		EnterpriseID: "ent_1",
		TaskRunID:    "task_1",
	})
	if err != nil {
		t.Fatalf("BuildOrgImportPreviewForTask returned error: %v", err)
	}
	if !preview.RequiresConfirmation {
		t.Fatal("RequiresConfirmation = false, want true")
	}
	if waiter.reason == "" || waiter.taskRunID != "task_1" {
		t.Fatalf("waiter = %+v, want task_1 with reason", waiter)
	}
}

type recordingConfirmationWaiter struct {
	taskRunID string
	reason    string
}

func (w *recordingConfirmationWaiter) WaitForConfirmation(_ context.Context, input tasks.WaitForConfirmationInput) (tasks.TaskRun, error) {
	w.taskRunID = input.TaskRunID
	w.reason = input.Reason
	return tasks.TaskRun{ID: input.TaskRunID, Status: tasks.TaskStatusWaitingConfirmation}, nil
}
