package manifest

import connector "github.com/astraclawteam/agentnexus/sdk/go/connector"

func Validate(manifest connector.Manifest) error {
	return connector.ValidateManifest(manifest)
}
