package app

import (
	"context"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/orgsource"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

func BuildOrgImportPreview(ctx context.Context, provider orgsource.Provider) (orgsource.ImportPreview, error) {
	snapshot, err := provider.Fetch(ctx)
	if err != nil {
		return orgsource.ImportPreview{}, err
	}
	return orgsource.PreviewImport(snapshot), nil
}

type OrgImportTaskContext struct {
	EnterpriseID string
	TaskRunID    string
}

type ConfirmationWaiter interface {
	WaitForConfirmation(context.Context, tasks.WaitForConfirmationInput) (tasks.TaskRun, error)
}

func BuildOrgImportPreviewForTask(ctx context.Context, provider orgsource.Provider, waiter ConfirmationWaiter, taskContext OrgImportTaskContext) (orgsource.ImportPreview, error) {
	preview, err := BuildOrgImportPreview(ctx, provider)
	if err != nil {
		return orgsource.ImportPreview{}, err
	}
	if preview.RequiresConfirmation && waiter != nil {
		if _, err := waiter.WaitForConfirmation(ctx, tasks.WaitForConfirmationInput{
			EnterpriseID: taskContext.EnterpriseID,
			TaskRunID:    taskContext.TaskRunID,
			Reason:       preview.ConfirmationReason,
		}); err != nil {
			return orgsource.ImportPreview{}, err
		}
	}
	return preview, nil
}
