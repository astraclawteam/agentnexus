package runtime

import (
	"testing"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

func TestSchemaAndMaskingValidation(t *testing.T) {
	resource := connector.Resource{
		Name:         "contracts",
		OutputSchema: map[string]any{"type": "object"},
		Fields: []connector.Field{
			{Name: "title", Type: "string"},
			{Name: "body", Type: "string", Mask: true},
		},
	}
	if !ValidateOutputSchema(resource) {
		t.Fatal("ValidateOutputSchema = false, want true")
	}
	if !ValidateMasking(resource, []string{"title", "body"}) {
		t.Fatal("ValidateMasking = false, want true")
	}
	if ValidateMasking(resource, []string{"title"}) {
		t.Fatal("ValidateMasking = true when masked field is omitted")
	}
}

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(1)
	if !limiter.Allow("connector_1") {
		t.Fatal("first Allow = false, want true")
	}
	if limiter.Allow("connector_1") {
		t.Fatal("second Allow = true, want false")
	}
	if !limiter.Allow("connector_2") {
		t.Fatal("different connector Allow = false, want true")
	}
}
