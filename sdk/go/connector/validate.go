package connector

import "fmt"

func ValidateManifest(manifest Manifest) error {
	if manifest.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}
	if manifest.Name == "" {
		return fmt.Errorf("name is required")
	}
	if manifest.Version == "" {
		return fmt.Errorf("version is required")
	}
	if len(manifest.Resources) == 0 {
		return fmt.Errorf("at least one resource is required")
	}

	resourceNames := map[string]struct{}{}
	for _, resource := range manifest.Resources {
		if resource.Name == "" {
			return fmt.Errorf("resource name is required")
		}
		if _, ok := resourceNames[resource.Name]; ok {
			return fmt.Errorf("duplicate resource %q", resource.Name)
		}
		resourceNames[resource.Name] = struct{}{}
		if resource.Type == "" {
			return fmt.Errorf("resource %q type is required", resource.Name)
		}
		if resource.Executable != nil && resource.Executable.Upload {
			return fmt.Errorf("resource %q executable code upload is not allowed", resource.Name)
		}
		fieldNames := map[string]struct{}{}
		for _, field := range resource.Fields {
			if field.Name == "" {
				return fmt.Errorf("resource %q field name is required", resource.Name)
			}
			if _, ok := fieldNames[field.Name]; ok {
				return fmt.Errorf("resource %q duplicate field %q", resource.Name, field.Name)
			}
			fieldNames[field.Name] = struct{}{}
		}
		operationNames := map[string]struct{}{}
		for _, operation := range resource.Operations {
			if operation.Name == "" {
				return fmt.Errorf("resource %q operation name is required", resource.Name)
			}
			operationNames[operation.Name] = struct{}{}
		}
		for _, smokeTest := range resource.SmokeTests {
			if smokeTest.Operation == "" {
				return fmt.Errorf("resource %q smoke test operation is required", resource.Name)
			}
			if _, ok := operationNames[smokeTest.Operation]; !ok {
				return fmt.Errorf("resource %q undeclared smoke operation %q", resource.Name, smokeTest.Operation)
			}
			for _, field := range smokeTest.Fields {
				if _, ok := fieldNames[field]; !ok {
					return fmt.Errorf("resource %q undeclared smoke field %q", resource.Name, field)
				}
			}
		}
		if resource.Risk.Level == RiskHigh && (len(resource.InputSchema) == 0 || len(resource.OutputSchema) == 0) {
			return fmt.Errorf("resource %q high-risk resource requires input_schema and output_schema", resource.Name)
		}
	}
	return nil
}

func JSONSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"schema_version", "name", "version", "resources"},
		"properties": map[string]any{
			"schema_version": map[string]any{"type": "string"},
			"name":           map[string]any{"type": "string"},
			"version":        map[string]any{"type": "string"},
			"resources":      map[string]any{"type": "array"},
			"credentials":    map[string]any{"type": "array"},
		},
	}
}
