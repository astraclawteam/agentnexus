package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/authorization"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

func TestRuntimeLocateCreatesDurableTaskRunAndEvent(t *testing.T) {
	taskStore := tasks.NewMemoryStore()
	taskPublisher := &runtimeTaskEventRecorder{}
	runtime := NewAuthorizedRuntimeAPI(AuthorizedRuntimeConfig{
		Authorizer:       authorization.NewAuthorizer(authorization.NewInMemoryRelationshipChecker()),
		PolicyEvaluator:  policy.NewEvaluator(policy.Policy{}),
		TicketService:    tickets.NewService(tickets.NewMemoryStore(), tickets.WithIDGenerator(runtimeSequenceIDs("case_ticket_1"))),
		AuditSink:        audit.NewHashChainLog(audit.WithIDGenerator(runtimeSequenceIDs("audit_1"))),
		TaskOrchestrator: tasks.NewOrchestrator(taskStore, taskPublisher, tasks.WithIDGenerator(runtimeSequenceIDs("task_1"))),
		DataProvider:     StaticRuntimeDataProvider{},
	})
	mux := http.NewServeMux()
	RegisterRuntimeAPIRoutes(mux, runtime)

	body := []byte(`{
		"enterprise_id": "ent_1",
		"actor_user_id": "user_1",
		"request_id": "req_1",
		"trace_id": "trace_1",
		"intent": "find production work orders"
	}`)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/runtime/locate", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CaseTicketID string `json:"case_ticket_id"`
		TaskRunID    string `json:"task_run_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if resp.CaseTicketID != "case_ticket_1" || resp.TaskRunID != "task_1" {
		t.Fatalf("response = %+v", resp)
	}

	run, err := taskStore.GetTaskRun(context.Background(), "ent_1", "task_1")
	if err != nil {
		t.Fatalf("GetTaskRun returned error: %v", err)
	}
	if run.ActorUserID != "user_1" || run.RequestID != "req_1" || run.TraceID != "trace_1" || run.Status != tasks.TaskStatusQueued {
		t.Fatalf("task run = %+v", run)
	}
	if len(taskPublisher.events) != 1 || taskPublisher.events[0].Subject != tasks.SubjectTaskCreated {
		t.Fatalf("task events = %+v", taskPublisher.events)
	}
}

type runtimeTaskEventRecorder struct {
	events []tasks.TaskEvent
}

func (r *runtimeTaskEventRecorder) PublishTaskEvent(_ context.Context, event tasks.TaskEvent) error {
	r.events = append(r.events, event)
	return nil
}

func runtimeSequenceIDs(ids ...string) func() string {
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
