package config

import "os"

const DefaultVersion = "0.1.0-dev"

type Config struct {
	ServiceName    string
	Version        string
	Environment    string
	HTTPAddr       string
	Postgres       PostgresConfig
	NATS           NATSConfig
	ObjectStorage  ObjectStorageConfig
	SecretProvider SecretProviderConfig
	LLMRouter      LLMRouterConfig
}

type PostgresConfig struct {
	DSN string
}

type NATSConfig struct {
	URL string
}

type ObjectStorageConfig struct {
	Endpoint string
}

type SecretProviderConfig struct {
	Mode string
}

type LLMRouterConfig struct {
	BaseURL string
	Model   string
	APIKey  string
}

func Load(serviceName string) Config {
	version := os.Getenv("AGENTNEXUS_VERSION")
	if version == "" {
		version = DefaultVersion
	}

	environment := os.Getenv("AGENTNEXUS_ENV")
	if environment == "" {
		environment = "dev"
	}

	httpAddr := os.Getenv("AGENTNEXUS_HTTP_ADDR")
	if httpAddr == "" {
		httpAddr = ":8080"
	}

	return Config{
		ServiceName:    serviceName,
		Version:        version,
		Environment:    environment,
		HTTPAddr:       httpAddr,
		Postgres:       PostgresConfig{DSN: os.Getenv("AGENTNEXUS_POSTGRES_DSN")},
		NATS:           NATSConfig{URL: os.Getenv("AGENTNEXUS_NATS_URL")},
		ObjectStorage:  ObjectStorageConfig{Endpoint: os.Getenv("AGENTNEXUS_OBJECT_STORAGE_ENDPOINT")},
		SecretProvider: SecretProviderConfig{Mode: secretProviderMode()},
		LLMRouter:      LLMRouterConfig{BaseURL: os.Getenv("LLMROUTER_BASE_URL"), Model: os.Getenv("LLMROUTER_MODEL")},
	}
}

func secretProviderMode() string {
	mode := os.Getenv("AGENTNEXUS_SECRET_PROVIDER")
	if mode == "" {
		return "local-dev"
	}
	return mode
}
