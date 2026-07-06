package runtime

import connector "github.com/astraclawteam/agentnexus/sdk/go/connector"

func ValidateOutputSchema(resource connector.Resource) bool {
	return len(resource.OutputSchema) > 0 || resource.Risk.Level != connector.RiskHigh
}
