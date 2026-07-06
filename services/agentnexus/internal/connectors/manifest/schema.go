package manifest

import connector "github.com/astraclawteam/agentnexus/sdk/go/connector"

type Manifest = connector.Manifest
type Resource = connector.Resource
type Field = connector.Field
type Operation = connector.Operation

func JSONSchema() map[string]any {
	return connector.JSONSchema()
}
