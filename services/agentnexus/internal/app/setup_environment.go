package app

import (
	"os"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/secrets"
)

type setupEnvironmentReport struct {
	OverallStatus string                  `json:"overall_status"`
	Checks        []setupEnvironmentCheck `json:"checks"`
	GeneratedAt   string                  `json:"generated_at"`
}

type setupEnvironmentCheck struct {
	Key     string `json:"key"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

func BuildSetupEnvironmentReport() setupEnvironmentReport {
	checks := []setupEnvironmentCheck{
		{
			Key:     "gateway_api",
			Status:  "ready",
			Message: "gateway-api is serving this request.",
		},
		checkConfiguredURL("gateway_agent", "AGENTNEXUS_GATEWAY_AGENT_URL", "Gateway Agent URL is not configured yet. Configure it after starting gateway-agent."),
		checkConfiguredEnv("postgres", []string{"DATABASE_URL", "AGENTNEXUS_POSTGRES_DSN"}, "PostgreSQL is not configured. Private-dev can continue with in-memory stores, but production needs PostgreSQL."),
		checkConfiguredEnv("nats", []string{"NATS_URL", "AGENTNEXUS_NATS_URL"}, "NATS is not configured. Private-dev can continue for setup, but async workers need NATS."),
		{
			Key:     "secret_provider",
			Status:  "ready",
			Message: "Secret provider mode is env and accepts " + secrets.EnvRefPrefix + " references.",
		},
		checkComposeProfile(),
	}
	return setupEnvironmentReport{
		OverallStatus: deriveEnvironmentStatus(checks),
		Checks:        checks,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	}
}

func checkConfiguredURL(key, envName, warning string) setupEnvironmentCheck {
	if os.Getenv(envName) != "" {
		return setupEnvironmentCheck{
			Key:     key,
			Status:  "ready",
			Message: envName + " is configured.",
		}
	}
	return setupEnvironmentCheck{
		Key:     key,
		Status:  "warning",
		Message: warning,
		Fix:     "Set " + envName + " in the private deployment environment and retry.",
	}
}

func checkConfiguredEnv(key string, envNames []string, warning string) setupEnvironmentCheck {
	for _, envName := range envNames {
		if os.Getenv(envName) != "" {
			return setupEnvironmentCheck{
				Key:     key,
				Status:  "ready",
				Message: envName + " is configured.",
			}
		}
	}
	return setupEnvironmentCheck{
		Key:     key,
		Status:  "warning",
		Message: warning,
		Fix:     "Set one of " + joinEnvNames(envNames) + " in the deployment environment and retry.",
	}
}

func checkComposeProfile() setupEnvironmentCheck {
	const composeFile = "deploy/compose/compose.private-dev.yaml"
	if _, err := os.Stat(composeFile); err == nil {
		return setupEnvironmentCheck{
			Key:     "compose_profile",
			Status:  "ready",
			Message: "Private-dev Docker Compose profile is available.",
		}
	}
	return setupEnvironmentCheck{
		Key:     "compose_profile",
		Status:  "warning",
		Message: "Private-dev Docker Compose profile was not found from the current working directory.",
		Fix:     "Run gateway-api from services/agentnexus or verify deploy/compose/compose.private-dev.yaml exists.",
	}
}

func deriveEnvironmentStatus(checks []setupEnvironmentCheck) string {
	overall := "ready"
	for _, check := range checks {
		if check.Status == "blocked" {
			return "blocked"
		}
		if check.Status == "warning" {
			overall = "warning"
		}
	}
	return overall
}

func joinEnvNames(values []string) string {
	if len(values) == 0 {
		return ""
	}
	result := values[0]
	for _, value := range values[1:] {
		result += " or " + value
	}
	return result
}

