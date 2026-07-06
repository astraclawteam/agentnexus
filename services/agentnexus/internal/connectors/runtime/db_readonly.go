package runtime

import (
	"context"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

type dbReadonlyAdapter struct{}

func (dbReadonlyAdapter) Name() string {
	return "db_readonly"
}

func (dbReadonlyAdapter) Execute(_ context.Context, resource connector.Resource, req Request) (map[string]any, error) {
	return map[string]any{
		"resource":  resource.Name,
		"operation": req.Operation,
	}, nil
}
