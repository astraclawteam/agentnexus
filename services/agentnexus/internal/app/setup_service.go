package app

import (
	"context"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

type SetupService struct {
	store      setupEnterpriseStore
	iamService *iam.Service
}

type setupStatusResponse struct {
	State               string                  `json:"state"`
	EnterpriseID        string                  `json:"enterprise_id"`
	EnterpriseName      string                  `json:"enterprise_name"`
	AdminUserID         string                  `json:"admin_user_id"`
	EnvironmentLabel    string                  `json:"environment_label"`
	Session             setupSession            `json:"session"`
	SecretProvider      setupSecretSource       `json:"secret_provider"`
	Environment         setupEnvironmentReport  `json:"environment"`
	Checklist           []setupChecklistItem    `json:"checklist"`
	Services            map[string]string       `json:"services"`
	NextRequiredActions []string                `json:"next_required_actions"`
}

type setupSession struct {
	Mode        string `json:"mode"`
	ActorUserID string `json:"actor_user_id"`
	Secure      bool   `json:"secure"`
	Message     string `json:"message"`
}

type setupSecretSource struct {
	Mode                string   `json:"mode"`
	Writable            bool     `json:"writable"`
	AcceptedRefPrefixes []string `json:"accepted_ref_prefixes"`
}

type setupChecklistItem struct {
	Key      string `json:"key"`
	Status   string `json:"status"`
	Required bool   `json:"required"`
	Title    string `json:"title"`
	Action   string `json:"action"`
	Message  string `json:"message,omitempty"`
}

func NewSetupService(store setupEnterpriseStore, iamService *iam.Service) *SetupService {
	return &SetupService{store: store, iamService: iamService}
}

func (s *SetupService) Status(ctx context.Context) setupStatusResponse {
	environment := BuildSetupEnvironmentReport()
	secretProvider := setupSecretSource{Mode: "env", Writable: false, AcceptedRefPrefixes: []string{secrets.EnvRefPrefix}}
	if s == nil || s.store == nil {
		return setupStatusResponse{
			State:               "unconfigured",
			Session:             defaultDevAdminSession("admin_dev"),
			SecretProvider:      secretProvider,
			Environment:         environment,
			Checklist:           buildSetupChecklist("unconfigured", false, environment),
			Services:            environmentServices(environment),
			NextRequiredActions: []string{"create_enterprise", "configure_secret_refs", "import_org"},
		}
	}

	configured, ok := s.store.First()
	if !ok {
		return setupStatusResponse{
			State:               "unconfigured",
			Session:             defaultDevAdminSession("admin_dev"),
			SecretProvider:      secretProvider,
			Environment:         environment,
			Checklist:           buildSetupChecklist("unconfigured", false, environment),
			Services:            environmentServices(environment),
			NextRequiredActions: []string{"create_enterprise", "configure_secret_refs", "import_org"},
		}
	}

	state := "configured_without_org"
	hasOrgGraph := false
	nextActions := []string{"configure_secret_refs", "import_org"}
	if s.iamService != nil {
		graph, err := s.iamService.GetOrgGraph(ctx, configured.EnterpriseID)
		if err == nil && (len(graph.Departments) > 0 || len(graph.Users) > 0 || len(graph.Memberships) > 0) {
			state = "configured"
			hasOrgGraph = true
			nextActions = []string{"configure_connectors", "configure_policy", "run_agent_deployment_plan"}
		}
	}

	return setupStatusResponse{
		State:               state,
		EnterpriseID:        configured.EnterpriseID,
		EnterpriseName:      configured.EnterpriseName,
		AdminUserID:         configured.AdminUserID,
		EnvironmentLabel:    configured.EnvironmentLabel,
		Session:             defaultDevAdminSession(configured.AdminUserID),
		SecretProvider:      secretProvider,
		Environment:         environment,
		Checklist:           buildSetupChecklist(state, hasOrgGraph, environment),
		Services:            environmentServices(environment),
		NextRequiredActions: nextActions,
	}
}

func defaultDevAdminSession(actorUserID string) setupSession {
	if actorUserID == "" {
		actorUserID = "admin_dev"
	}
	return setupSession{
		Mode:        "dev_admin",
		ActorUserID: actorUserID,
		Secure:      false,
		Message:     "Development admin session is active. This is not production authentication.",
	}
}

func buildSetupChecklist(state string, hasOrgGraph bool, environment setupEnvironmentReport) []setupChecklistItem {
	environmentStatus := "completed"
	if environment.OverallStatus == "blocked" {
		environmentStatus = "blocked"
	} else if environment.OverallStatus == "warning" {
		environmentStatus = "warning"
	}

	items := []setupChecklistItem{
		{
			Key:      "enterprise_tenant",
			Status:   "completed",
			Required: true,
			Title:    "Create enterprise tenant",
			Action:   "save_enterprise_tenant",
			Message:  "Create the company-scoped tenant boundary.",
		},
		{
			Key:      "environment_check",
			Status:   environmentStatus,
			Required: true,
			Title:    "Check offline runtime",
			Action:   "run_environment_check",
			Message:  "Verify local gateway, worker, database, and secret provider readiness.",
		},
		{
			Key:      "secret_refs",
			Status:   "required",
			Required: true,
			Title:    "Validate secret references",
			Action:   "validate_secret_refs",
			Message:  "Use secret references instead of raw API keys or tokens.",
		},
		{
			Key:      "organization_import",
			Status:   "required",
			Required: true,
			Title:    "Import organization data",
			Action:   "preview_org_import",
			Message:  "Preview employees and departments before confirming import.",
		},
		{
			Key:      "connector_verification",
			Status:   "recommended",
			Required: false,
			Title:    "Verify connector runtime",
			Action:   "run_connector_smoke",
			Message:  "Validate a connector manifest and run a smoke read.",
		},
		{
			Key:      "gateway_agent_dry_run",
			Status:   "recommended",
			Required: false,
			Title:    "Generate Gateway Agent dry-run",
			Action:   "generate_agent_dry_run",
			Message:  "Plan the first deployment without applying changes.",
		},
	}

	switch state {
	case "unconfigured":
		items[0].Status = "required"
		items[2].Status = "blocked"
		items[3].Status = "blocked"
		items[4].Status = "blocked"
		items[5].Status = "blocked"
	case "configured_without_org":
		items[3].Status = "required"
		items[4].Status = "blocked"
		items[5].Status = "blocked"
	case "configured":
		items[3].Status = "completed"
		if hasOrgGraph {
			items[2].Status = "warning"
		}
	}
	return items
}

func environmentServices(environment setupEnvironmentReport) map[string]string {
	services := make(map[string]string, len(environment.Checks))
	for _, check := range environment.Checks {
		services[check.Key] = check.Status
	}
	return services
}

