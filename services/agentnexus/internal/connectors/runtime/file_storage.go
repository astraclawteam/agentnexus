package runtime

import (
	"context"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

type fileStorageAdapter struct{}

func (fileStorageAdapter) Name() string {
	return "file_storage"
}

func (fileStorageAdapter) Execute(_ context.Context, resource connector.Resource, req Request) (map[string]any, error) {
	return map[string]any{
		"resource":  resource.Name,
		"operation": req.Operation,
	}, nil
}
