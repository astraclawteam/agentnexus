package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFirstDeploymentPlanPrivateDevComposeProfile(t *testing.T) {
	plan := BuildFirstDeploymentPlan(FirstDeploymentPlanInput{
		Profile:     "private-dev",
		ComposeFile: "deploy/compose/compose.private-dev.yaml",
	})

	if plan.Profile != "private-dev" {
		t.Fatalf("profile = %q, want private-dev", plan.Profile)
	}
	if plan.Mode != "dry_run" {
		t.Fatalf("mode = %q, want dry_run", plan.Mode)
	}
	if !plan.RequiresConfirmation {
		t.Fatal("requires_confirmation = false, want true")
	}

	wantNames := []string{
		"validate_compose_config",
		"start_gateway_api",
		"start_gateway_agent",
		"start_connector_worker",
		"verify_console_overview_api",
		"human_confirmation_before_apply",
	}
	if len(plan.Steps) != len(wantNames) {
		t.Fatalf("step count = %d, want %d: %#v", len(plan.Steps), len(wantNames), plan.Steps)
	}
	for i, want := range wantNames {
		if plan.Steps[i].Name != want {
			t.Fatalf("step[%d].Name = %q, want %q", i, plan.Steps[i].Name, want)
		}
	}
	if plan.Steps[0].Command != "docker compose -f deploy/compose/compose.private-dev.yaml config" {
		t.Fatalf("first command = %q", plan.Steps[0].Command)
	}
}

func TestGatewayAgentFirstDeploymentPlanRoute(t *testing.T) {
	router := NewGatewayAgentRouter("gateway-agent", "test")
	body := []byte(`{"profile":"private-dev","compose_file":"deploy/compose/compose.private-dev.yaml"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/deployments/first-run:plan", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp DeploymentPlan
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if resp.Profile != "private-dev" || resp.Mode != "dry_run" || !resp.RequiresConfirmation {
		t.Fatalf("unexpected response: %#v", resp)
	}
	if len(resp.Steps) == 0 || resp.Steps[0].Name != "validate_compose_config" {
		t.Fatalf("unexpected steps: %#v", resp.Steps)
	}
}

func TestGatewayAgentFirstDeploymentPlanRouteDefaultsEmptyBody(t *testing.T) {
	router := NewGatewayAgentRouter("gateway-agent", "test")
	req := httptest.NewRequest(http.MethodPost, "/v1/agent/deployments/first-run:plan", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp DeploymentPlan
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response json error = %v", err)
	}
	if resp.Profile != "private-dev" {
		t.Fatalf("profile = %q, want private-dev", resp.Profile)
	}
}
