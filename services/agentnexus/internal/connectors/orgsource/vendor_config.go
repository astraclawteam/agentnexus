package orgsource

import (
	"context"
	"net/http"
)

type TokenResolver interface {
	ResolveToken(context.Context, string) (string, error)
}

type TokenResolverFunc func(context.Context, string) (string, error)

func (fn TokenResolverFunc) ResolveToken(ctx context.Context, credentialRef string) (string, error) {
	return fn(ctx, credentialRef)
}

type VendorHTTPConfig struct {
	BaseURL         string
	DepartmentsPath string
	EmployeesPath   string
	CredentialRef   string
	HTTPClient      *http.Client
	TokenResolver   TokenResolver
}

type vendorHTTPProvider struct {
	name   string
	config VendorHTTPConfig
}

func newVendorHTTPProvider(name string, config VendorHTTPConfig) Provider {
	return vendorHTTPProvider{name: name, config: config}
}

func (p vendorHTTPProvider) Name() string {
	return p.name
}

func (p vendorHTTPProvider) Fetch(ctx context.Context) (Snapshot, error) {
	token := ""
	if p.config.CredentialRef != "" && p.config.TokenResolver != nil {
		resolved, err := p.config.TokenResolver.ResolveToken(ctx, p.config.CredentialRef)
		if err != nil {
			return Snapshot{}, err
		}
		token = resolved
	}
	return NewOAHTTPProvider(OAHTTPConfig{
		BaseURL:         p.config.BaseURL,
		DepartmentsPath: p.config.DepartmentsPath,
		EmployeesPath:   p.config.EmployeesPath,
		Token:           token,
		HTTPClient:      p.config.HTTPClient,
	}).Fetch(ctx)
}
