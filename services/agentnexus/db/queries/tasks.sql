-- name: CreateTaskRun :one
INSERT INTO task_runs (id, enterprise_id, actor_user_id, request_id, trace_id, status)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, enterprise_id, actor_user_id, request_id, trace_id, status, created_at, updated_at;

-- name: GetTaskRun :one
SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, created_at, updated_at
FROM task_runs
WHERE enterprise_id = $1 AND id = $2;

-- name: ListTaskRuns :many
SELECT id, enterprise_id, actor_user_id, request_id, trace_id, status, created_at, updated_at
FROM task_runs
WHERE enterprise_id = $1
ORDER BY created_at DESC;

-- name: CreateTaskStep :one
INSERT INTO task_steps (id, enterprise_id, task_run_id, name, status, input_hash, output_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, enterprise_id, task_run_id, name, status, input_hash, output_hash, created_at, updated_at;
