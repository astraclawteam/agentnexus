package runtime

import connector "github.com/astraclawteam/agentnexus/sdk/go/connector"

func ValidateMasking(resource connector.Resource, fields []string) bool {
	requested := map[string]struct{}{}
	for _, field := range fields {
		requested[field] = struct{}{}
	}
	hasMaskedField := false
	for _, field := range resource.Fields {
		if !field.Mask {
			continue
		}
		hasMaskedField = true
		if _, ok := requested[field.Name]; ok {
			return true
		}
	}
	return !hasMaskedField
}
