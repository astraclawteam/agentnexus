package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/storage"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

func TestPostgresTaskStorePersistsTaskLifecycle(t *testing.T) {
	dsn := os.Getenv("AGENTNEXUS_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("AGENTNEXUS_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	adminPool, err := storage.OpenPostgres(ctx, storage.PostgresConfig{DSN: dsn})
	if err != nil {
		t.Fatalf("open admin postgres pool: %v", err)
	}
	defer adminPool.Close()

	schema := fmt.Sprintf("agentnexus_task_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer adminPool.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)

	pool, err := storage.OpenPostgres(ctx, storage.PostgresConfig{
		DSN:        dsn,
		SearchPath: schema,
	})
	if err != nil {
		t.Fatalf("open schema postgres pool: %v", err)
	}
	defer pool.Close()

	if err := storage.ApplyEmbeddedMigrations(ctx, pool); err != nil {
		t.Fatalf("apply embedded migrations: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO enterprises (id, name) VALUES ($1, $2)`, "ent_1", "Enterprise 1"); err != nil {
		t.Fatalf("insert enterprise: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO enterprise_users (id, enterprise_id, display_name) VALUES ($1, $2, $3)`, "user_1", "ent_1", "User 1"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	store := tasks.NewPostgresStore(pool)
	run, err := store.CreateTaskRun(ctx, tasks.TaskRun{
		ID:           "task_1",
		EnterpriseID: "ent_1",
		ActorUserID:  "user_1",
		RequestID:    "req_1",
		TraceID:      "trace_1",
		Status:       tasks.TaskStatusQueued,
	})
	if err != nil {
		t.Fatalf("CreateTaskRun returned error: %v", err)
	}
	if run.ID != "task_1" || run.Status != tasks.TaskStatusQueued {
		t.Fatalf("run = %+v", run)
	}

	if _, err := store.AppendTaskStep(ctx, tasks.TaskStep{
		ID:           "step_1",
		EnterpriseID: "ent_1",
		TaskRunID:    "task_1",
		Name:         "collect_context",
		Status:       tasks.TaskStatusRunning,
		InputHash:    "sha256:in",
		OutputHash:   "sha256:out",
	}); err != nil {
		t.Fatalf("AppendTaskStep returned error: %v", err)
	}

	updated, err := store.UpdateTaskRunStatus(ctx, "ent_1", "task_1", tasks.TaskStatusRunning)
	if err != nil {
		t.Fatalf("UpdateTaskRunStatus returned error: %v", err)
	}
	if updated.Status != tasks.TaskStatusRunning {
		t.Fatalf("updated status = %q", updated.Status)
	}

	waiting, err := store.UpdateTaskRunStatus(ctx, "ent_1", "task_1", tasks.TaskStatusWaitingConfirmation)
	if err != nil {
		t.Fatalf("UpdateTaskRunStatus waiting returned error: %v", err)
	}
	if waiting.Status != tasks.TaskStatusWaitingConfirmation {
		t.Fatalf("waiting status = %q", waiting.Status)
	}
	if _, err := store.CreateConfirmationCheckpoint(ctx, tasks.ConfirmationCheckpoint{
		ID:           "checkpoint_1",
		EnterpriseID: "ent_1",
		TaskRunID:    "task_1",
		TaskStepID:   "step_1",
		Status:       tasks.ConfirmationStatusPending,
		Reason:       "high risk operation requires approval",
	}); err != nil {
		t.Fatalf("CreateConfirmationCheckpoint returned error: %v", err)
	}

	reloadedStore := tasks.NewPostgresStore(pool)
	reloaded, err := reloadedStore.GetTaskRun(ctx, "ent_1", "task_1")
	if err != nil {
		t.Fatalf("GetTaskRun after reload returned error: %v", err)
	}
	if reloaded.TraceID != "trace_1" || reloaded.Status != tasks.TaskStatusWaitingConfirmation {
		t.Fatalf("reloaded = %+v", reloaded)
	}
}
