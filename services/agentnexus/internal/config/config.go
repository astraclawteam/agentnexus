package config

import "os"

const DefaultVersion = "0.1.0-dev"

type Config struct {
	ServiceName string
	Version     string
	Environment string
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

	return Config{
		ServiceName: serviceName,
		Version:     version,
		Environment: environment,
	}
}
