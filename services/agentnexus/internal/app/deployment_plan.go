package app

type FirstDeploymentPlanInput struct {
	Profile     string `json:"profile"`
	ComposeFile string `json:"compose_file"`
}

type DeploymentPlan struct {
	Profile              string               `json:"profile"`
	Mode                 string               `json:"mode"`
	Steps                []DeploymentPlanStep `json:"steps"`
	RequiresConfirmation bool                 `json:"requires_confirmation"`
}

type DeploymentPlanStep struct {
	Name        string `json:"name"`
	Command     string `json:"command,omitempty"`
	Description string `json:"description,omitempty"`
}

func BuildFirstDeploymentPlan(input FirstDeploymentPlanInput) DeploymentPlan {
	profile := input.Profile
	if profile == "" {
		profile = "private-dev"
	}
	composeFile := input.ComposeFile
	if composeFile == "" {
		composeFile = "deploy/compose/compose.private-dev.yaml"
	}

	return DeploymentPlan{
		Profile: profile,
		Mode:    "dry_run",
		Steps: []DeploymentPlanStep{
			{
				Name:        "validate_compose_config",
				Command:     "docker compose -f " + composeFile + " config",
				Description: "Validate the dev Docker Compose profile before any service start.",
			},
			{
				Name:        "start_gateway_api",
				Command:     "docker compose -f " + composeFile + " up -d gateway-api",
				Description: "Start the gateway-api service after compose validation.",
			},
			{
				Name:        "start_gateway_agent",
				Command:     "docker compose -f " + composeFile + " up -d gateway-agent",
				Description: "Start the gateway-agent HTTP service for agent-run planning.",
			},
			{
				Name:        "start_connector_worker",
				Command:     "docker compose -f " + composeFile + " up -d connector-worker",
				Description: "Start the connector-worker for connector runtime checks.",
			},
			{
				Name:        "verify_console_overview_api",
				Command:     "Invoke-RestMethod http://127.0.0.1:8080/api/console/overview",
				Description: "Verify the console overview API responds in the dev profile.",
			},
			{
				Name:        "human_confirmation_before_apply",
				Description: "Require a human confirmation before any future apply operation.",
			},
		},
		RequiresConfirmation: true,
	}
}
