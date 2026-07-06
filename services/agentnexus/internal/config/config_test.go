package config

import "testing"

func TestLoadIncludesPlatformAndModelConfig(t *testing.T) {
	t.Setenv("AGENTNEXUS_VERSION", "1.2.3")
	t.Setenv("AGENTNEXUS_ENV", "private-dev")
	t.Setenv("AGENTNEXUS_HTTP_ADDR", ":9090")
	t.Setenv("AGENTNEXUS_POSTGRES_DSN", "postgres://agentnexus:agentnexus@localhost:5432/agentnexus")
	t.Setenv("AGENTNEXUS_NATS_URL", "nats://localhost:4222")
	t.Setenv("AGENTNEXUS_OBJECT_STORAGE_ENDPOINT", "http://localhost:9000")
	t.Setenv("AGENTNEXUS_SECRET_PROVIDER", "local-encrypted")
	t.Setenv("LLMROUTER_BASE_URL", "https://llmrouter.example.test")
	t.Setenv("LLMROUTER_MODEL", "agentnexus-test")

	cfg := Load("gateway-agent")

	if cfg.ServiceName != "gateway-agent" || cfg.Version != "1.2.3" || cfg.Environment != "private-dev" || cfg.HTTPAddr != ":9090" {
		t.Fatalf("basic config = %+v", cfg)
	}
	if cfg.Postgres.DSN != "postgres://agentnexus:agentnexus@localhost:5432/agentnexus" {
		t.Fatalf("postgres dsn = %q", cfg.Postgres.DSN)
	}
	if cfg.NATS.URL != "nats://localhost:4222" {
		t.Fatalf("nats url = %q", cfg.NATS.URL)
	}
	if cfg.ObjectStorage.Endpoint != "http://localhost:9000" {
		t.Fatalf("object storage endpoint = %q", cfg.ObjectStorage.Endpoint)
	}
	if cfg.SecretProvider.Mode != "local-encrypted" {
		t.Fatalf("secret provider mode = %q", cfg.SecretProvider.Mode)
	}
	if cfg.LLMRouter.BaseURL != "https://llmrouter.example.test" || cfg.LLMRouter.Model != "agentnexus-test" {
		t.Fatalf("llmrouter config = %+v", cfg.LLMRouter)
	}
	if cfg.LLMRouter.APIKey != "" {
		t.Fatal("Load should not expose LLMROUTER_API_KEY through Config")
	}
}
