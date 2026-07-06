package secrets

import (
	"context"
	"testing"
)

func TestEnvProviderResolvesSecretRefsOnly(t *testing.T) {
	t.Setenv("AGENTNEXUS_SECRET_DEMO", "resolved-secret")
	provider := EnvProvider{}

	value, err := provider.ResolveSecret(context.Background(), "secret://env/AGENTNEXUS_SECRET_DEMO")
	if err != nil {
		t.Fatalf("ResolveSecret returned error: %v", err)
	}
	if value != "resolved-secret" {
		t.Fatalf("value = %q, want resolved-secret", value)
	}

	if _, err := provider.ResolveSecret(context.Background(), "resolved-secret"); err == nil {
		t.Fatal("ResolveSecret accepted raw secret value")
	}
}
