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

type EnvProvider struct{}

func (EnvProvider) ResolveSecret(_ context.Context, ref string) (string, error) {
	const prefix = "secret://env/"
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Errorf("secret ref must use %s", prefix)
	}
	name := strings.TrimPrefix(ref, prefix)
	if name == "" {
		return "", fmt.Errorf("secret env name is required")
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("secret env %q is not set", name)
	}
	return value, nil
}
