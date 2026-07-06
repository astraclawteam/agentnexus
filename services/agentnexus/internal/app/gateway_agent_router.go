package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/agent"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/observability"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tasks"
)

func NewGatewayAgentRouter(serviceName, version string) http.Handler {
	return NewGatewayAgentRouterWithAgentService(serviceName, version, agent.NewService(tasks.NewOrchestrator(tasks.NewMemoryStore(), nil)))
}

func NewGatewayAgentRouterWithAgentService(serviceName, version string, agentService *agent.Service) http.Handler {
	mux := http.NewServeMux()
	health := NewHealthStatus(serviceName, version, true)
	if agentService == nil {
		agentService = agent.NewService(nil)
	}

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(observability.PrometheusText(observability.Snapshot{
			Service: serviceName,
			Ready:   true,
		})))
	})
	mux.HandleFunc("POST /v1/agent/deployments/first-run:plan", func(w http.ResponseWriter, r *http.Request) {
		var input FirstDeploymentPlanInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		writeJSON(w, http.StatusOK, BuildFirstDeploymentPlan(input))
	})
	mux.HandleFunc("POST /v1/agent/runs", handleAgentRunStart(agentService))
	mux.HandleFunc("POST /v1/agent/runs/{id}/messages", handleAgentRunMessage(agentService))
	mux.HandleFunc("POST /v1/agent/runs/{id}/confirmations", handleAgentRunConfirmation(agentService))

	return mux
}

type agentRunStartRequest struct {
	EnterpriseID string `json:"enterprise_id"`
	ActorUserID  string `json:"actor_user_id"`
	RequestID    string `json:"request_id"`
	TraceID      string `json:"trace_id"`
	Goal         string `json:"goal"`
}

type agentRunStartResponse struct {
	AgentRunID string       `json:"agent_run_id"`
	TaskRunID  string       `json:"task_run_id"`
	Status     string       `json:"status"`
	Tools      []agent.Tool `json:"tools"`
}

type agentRunMessageRequest struct {
	EnterpriseID string `json:"enterprise_id"`
	Message      string `json:"message"`
}

type agentRunMessageResponse struct {
	AgentRunID string `json:"agent_run_id"`
	StepID     string `json:"step_id"`
	Status     string `json:"status"`
}

type agentRunConfirmationRequest struct {
	EnterpriseID string `json:"enterprise_id"`
	Reason       string `json:"reason"`
}

type agentRunConfirmationResponse struct {
	AgentRunID string `json:"agent_run_id"`
	Status     string `json:"status"`
}

func handleAgentRunStart(service *agent.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req agentRunStartRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		run, err := service.StartRun(r.Context(), agent.StartRunInput{
			EnterpriseID: req.EnterpriseID,
			ActorUserID:  req.ActorUserID,
			RequestID:    req.RequestID,
			TraceID:      req.TraceID,
			Goal:         req.Goal,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, agentRunStartResponse{
			AgentRunID: run.ID,
			TaskRunID:  run.ID,
			Status:     string(run.Status),
			Tools:      run.Tools,
		})
	}
}

func handleAgentRunMessage(service *agent.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req agentRunMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		result, err := service.AddMessage(r.Context(), agent.AddMessageInput{
			EnterpriseID: req.EnterpriseID,
			RunID:        r.PathValue("id"),
			Message:      req.Message,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, agentRunMessageResponse{
			AgentRunID: result.RunID,
			StepID:     result.StepID,
			Status:     string(result.Status),
		})
	}
}

func handleAgentRunConfirmation(service *agent.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req agentRunConfirmationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json request"})
			return
		}
		result, err := service.RequestConfirmation(r.Context(), agent.RequestConfirmationInput{
			EnterpriseID: req.EnterpriseID,
			RunID:        r.PathValue("id"),
			Reason:       req.Reason,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, agentRunConfirmationResponse{
			AgentRunID: result.RunID,
			Status:     string(result.Status),
		})
	}
}
