package runtime

import (
	"context"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

type httpOpenAPIAdapter struct{}

func (httpOpenAPIAdapter) Name() string {
	return "http_openapi"
}

func (httpOpenAPIAdapter) Execute(_ context.Context, resource connector.Resource, req Request) (map[string]any, error) {
	return map[string]any{
		"resource":  resource.Name,
		"operation": req.Operation,
	}, nil
}
