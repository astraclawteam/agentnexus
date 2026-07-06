package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/agent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

func TestGatewayAgentRunRoutes(t *testing.T) {
	agentService := agent.NewService(tasks.NewOrchestrator(tasks.NewMemoryStore(), nil, tasks.WithIDGenerator(runtimeSequenceIDs("run_1", "step_plan", "step_msg", "checkpoint_1"))))
	router := NewGatewayAgentRouterWithAgentService("gateway-agent", "test", agentService)

	runRec := httptest.NewRecorder()
	router.ServeHTTP(runRec, httptest.NewRequest(http.MethodPost, "/v1/agent/runs", bytes.NewReader([]byte(`{
		"enterprise_id":"ent_1",
		"actor_user_id":"user_ada",
		"request_id":"req_1",
		"trace_id":"trace_1",
		"goal":"preview OA import"
	}`))))
	if runRec.Code != http.StatusOK {
		t.Fatalf("run status = %d, body = %s", runRec.Code, runRec.Body.String())
	}
	var runResp struct {
		AgentRunID string       `json:"agent_run_id"`
		Status     string       `json:"status"`
		Tools      []agent.Tool `json:"tools"`
	}
	if err := json.Unmarshal(runRec.Body.Bytes(), &runResp); err != nil {
		t.Fatalf("run json error: %v", err)
	}
	if runResp.AgentRunID != "run_1" || runResp.Status != string(tasks.TaskStatusRunning) || len(runResp.Tools) == 0 {
		t.Fatalf("run response = %+v", runResp)
	}

	messageRec := httptest.NewRecorder()
	router.ServeHTTP(messageRec, httptest.NewRequest(http.MethodPost, "/v1/agent/runs/run_1/messages", bytes.NewReader([]byte(`{
		"enterprise_id":"ent_1",
		"message":"continue with connector smoke"
	}`))))
	if messageRec.Code != http.StatusOK {
		t.Fatalf("message status = %d, body = %s", messageRec.Code, messageRec.Body.String())
	}
	var messageResp struct {
		StepID string `json:"step_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(messageRec.Body.Bytes(), &messageResp); err != nil {
		t.Fatalf("message json error: %v", err)
	}
	if messageResp.StepID != "step_msg" || messageResp.Status != string(tasks.TaskStatusRunning) {
		t.Fatalf("message response = %+v", messageResp)
	}

	confirmationRec := httptest.NewRecorder()
	router.ServeHTTP(confirmationRec, httptest.NewRequest(http.MethodPost, "/v1/agent/runs/run_1/confirmations", bytes.NewReader([]byte(`{
		"enterprise_id":"ent_1",
		"reason":"approve dry-run plan"
	}`))))
	if confirmationRec.Code != http.StatusOK {
		t.Fatalf("confirmation status = %d, body = %s", confirmationRec.Code, confirmationRec.Body.String())
	}
	var confirmationResp struct {
		AgentRunID string `json:"agent_run_id"`
		Status     string `json:"status"`
	}
	if err := json.Unmarshal(confirmationRec.Body.Bytes(), &confirmationResp); err != nil {
		t.Fatalf("confirmation json error: %v", err)
	}
	if confirmationResp.AgentRunID != "run_1" || confirmationResp.Status != string(tasks.TaskStatusWaitingConfirmation) {
		t.Fatalf("confirmation response = %+v", confirmationResp)
	}
}
