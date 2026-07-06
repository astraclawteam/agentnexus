package tasks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store interface {
	CreateTaskRun(context.Context, TaskRun) (TaskRun, error)
	GetTaskRun(context.Context, string, string) (TaskRun, error)
	UpdateTaskRunStatus(context.Context, string, string, TaskStatus) (TaskRun, error)
	AppendTaskStep(context.Context, TaskStep) (TaskStep, error)
	CreateConfirmationCheckpoint(context.Context, ConfirmationCheckpoint) (ConfirmationCheckpoint, error)
}

type MemoryStore struct {
	mu          sync.Mutex
	runs        map[string]TaskRun
	steps       map[string]TaskStep
	checkpoints map[string]ConfirmationCheckpoint
	now         func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		runs:        map[string]TaskRun{},
		steps:       map[string]TaskStep{},
		checkpoints: map[string]ConfirmationCheckpoint{},
		now:         time.Now,
	}
}

func (s *MemoryStore) CreateTaskRun(_ context.Context, run TaskRun) (TaskRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()
	run.CreatedAt = now
	run.UpdatedAt = now
	s.runs[taskKey(run.EnterpriseID, run.ID)] = run
	return run, nil
}

func (s *MemoryStore) GetTaskRun(_ context.Context, enterpriseID, taskRunID string) (TaskRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	run, ok := s.runs[taskKey(enterpriseID, taskRunID)]
	if !ok {
		return TaskRun{}, ErrTaskNotFound
	}
	return run, nil
}

func (s *MemoryStore) UpdateTaskRunStatus(_ context.Context, enterpriseID, taskRunID string, status TaskStatus) (TaskRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := taskKey(enterpriseID, taskRunID)
	run, ok := s.runs[key]
	if !ok {
		return TaskRun{}, ErrTaskNotFound
	}
	run.Status = status
	run.UpdatedAt = s.now().UTC()
	s.runs[key] = run
	return run, nil
}

func (s *MemoryStore) AppendTaskStep(_ context.Context, step TaskStep) (TaskStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.runs[taskKey(step.EnterpriseID, step.TaskRunID)]; !ok {
		return TaskStep{}, ErrTaskNotFound
	}
	now := s.now().UTC()
	step.CreatedAt = now
	step.UpdatedAt = now
	s.steps[taskKey(step.EnterpriseID, step.ID)] = step
	return step, nil
}

func (s *MemoryStore) CreateConfirmationCheckpoint(_ context.Context, checkpoint ConfirmationCheckpoint) (ConfirmationCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.runs[taskKey(checkpoint.EnterpriseID, checkpoint.TaskRunID)]; !ok {
		return ConfirmationCheckpoint{}, ErrTaskNotFound
	}
	checkpoint.CreatedAt = s.now().UTC()
	s.checkpoints[taskKey(checkpoint.EnterpriseID, checkpoint.ID)] = checkpoint
	return checkpoint, nil
}

func (s *MemoryStore) ConfirmationCheckpointCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.checkpoints)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreateTaskRun(ctx context.Context, run TaskRun) (TaskRun, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO task_runs (id, enterprise_id, actor_user_id, request_id, trace_id, status)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, enterprise_id, actor_user_id, request_id, trace_id, status, created_at, updated_at`,
		run.ID, run.EnterpriseID, run.ActorUserID, run.RequestID, nullText(run.TraceID), run.Status)
	return scanTaskRun(row)
}

func (s *PostgresStore) GetTaskRun(ctx context.Context, enterpriseID, taskRunID string) (TaskRun, error) {
	row := s.pool.QueryRow(ctx, `
SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, created_at, updated_at
FROM task_runs
WHERE enterprise_id = $1 AND id = $2`, enterpriseID, taskRunID)
	return scanTaskRun(row)
}

func (s *PostgresStore) UpdateTaskRunStatus(ctx context.Context, enterpriseID, taskRunID string, status TaskStatus) (TaskRun, error) {
	row := s.pool.QueryRow(ctx, `
UPDATE task_runs
SET status = $3, updated_at = now()
WHERE enterprise_id = $1 AND id = $2
RETURNING id, enterprise_id, actor_user_id, request_id, trace_id, status, created_at, updated_at`, enterpriseID, taskRunID, status)
	return scanTaskRun(row)
}

func (s *PostgresStore) AppendTaskStep(ctx context.Context, step TaskStep) (TaskStep, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO task_steps (id, enterprise_id, task_run_id, name, status, input_hash, output_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, enterprise_id, task_run_id, name, status, input_hash, output_hash, created_at, updated_at`,
		step.ID, step.EnterpriseID, step.TaskRunID, step.Name, step.Status, nullText(step.InputHash), nullText(step.OutputHash))
	return scanTaskStep(row)
}

func (s *PostgresStore) CreateConfirmationCheckpoint(ctx context.Context, checkpoint ConfirmationCheckpoint) (ConfirmationCheckpoint, error) {
	row := s.pool.QueryRow(ctx, `
INSERT INTO confirmation_checkpoints (id, enterprise_id, task_run_id, task_step_id, status, reason)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, enterprise_id, task_run_id, task_step_id, status, reason, created_at, resolved_at`,
		checkpoint.ID, checkpoint.EnterpriseID, checkpoint.TaskRunID, nullText(checkpoint.TaskStepID), checkpoint.Status, checkpoint.Reason)
	return scanConfirmationCheckpoint(row)
}

type taskRunScanner interface {
	Scan(dest ...any) error
}

func scanTaskRun(row taskRunScanner) (TaskRun, error) {
	var run TaskRun
	var traceID pgtype.Text
	if err := row.Scan(&run.ID, &run.EnterpriseID, &run.ActorUserID, &run.RequestID, &traceID, &run.Status, &run.CreatedAt, &run.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return TaskRun{}, ErrTaskNotFound
		}
		return TaskRun{}, err
	}
	if traceID.Valid {
		run.TraceID = traceID.String
	}
	return run, nil
}

func scanTaskStep(row taskRunScanner) (TaskStep, error) {
	var step TaskStep
	var inputHash, outputHash pgtype.Text
	if err := row.Scan(&step.ID, &step.EnterpriseID, &step.TaskRunID, &step.Name, &step.Status, &inputHash, &outputHash, &step.CreatedAt, &step.UpdatedAt); err != nil {
		if err == pgx.ErrNoRows {
			return TaskStep{}, ErrTaskNotFound
		}
		return TaskStep{}, err
	}
	if inputHash.Valid {
		step.InputHash = inputHash.String
	}
	if outputHash.Valid {
		step.OutputHash = outputHash.String
	}
	return step, nil
}

func scanConfirmationCheckpoint(row taskRunScanner) (ConfirmationCheckpoint, error) {
	var checkpoint ConfirmationCheckpoint
	var taskStepID pgtype.Text
	if err := row.Scan(&checkpoint.ID, &checkpoint.EnterpriseID, &checkpoint.TaskRunID, &taskStepID, &checkpoint.Status, &checkpoint.Reason, &checkpoint.CreatedAt, &checkpoint.ResolvedAt); err != nil {
		if err == pgx.ErrNoRows {
			return ConfirmationCheckpoint{}, ErrTaskNotFound
		}
		return ConfirmationCheckpoint{}, err
	}
	if taskStepID.Valid {
		checkpoint.TaskStepID = taskStepID.String
	}
	return checkpoint, nil
}

func taskKey(enterpriseID, id string) string {
	return enterpriseID + ":" + id
}

func nullText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func randomID(prefix string) string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return prefix + "_" + hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return prefix + "_" + hex.EncodeToString(bytes[:])
}
