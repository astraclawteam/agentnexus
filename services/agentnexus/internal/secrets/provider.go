package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type Provider interface {
	ResolveSecret(context.Context, string) (string, error)
}

const EnvRefPrefix = "secret://env/"

type EnvProvider struct{}

func (EnvProvider) ResolveSecret(_ context.Context, ref string) (string, error) {
	if !strings.HasPrefix(ref, EnvRefPrefix) {
		return "", fmt.Errorf("secret ref must use %s", EnvRefPrefix)
	}
	name := strings.TrimPrefix(ref, EnvRefPrefix)
	if name == "" {
		return "", fmt.Errorf("secret env name is required")
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("secret env %q is not set", name)
	}
	return value, nil
}
