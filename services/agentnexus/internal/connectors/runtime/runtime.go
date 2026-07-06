package runtime

import (
	"context"
	"errors"
	"fmt"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

type Action string

const (
	ActionRead  Action = "read"
	ActionWrite Action = "write"
)

var (
	ErrUndeclaredResource = errors.New("undeclared connector resource")
	ErrUndeclaredField    = errors.New("undeclared connector field")
	ErrReadOnlyResource   = errors.New("read-only connector resource")
	ErrOperationNotFound  = errors.New("connector operation not found")
)

type Request struct {
	Resource      string
	Operation     string
	Action        Action
	Fields        []string
	CredentialRef string
}

type Result struct {
	Resource string
	Adapter  string
	Data     map[string]any
	Audit    AuditContext
}

type AuditContext struct {
	Resource           string
	Operation          string
	Action             Action
	Fields             []string
	CredentialResolved bool
}

type SecretResolver interface {
	ResolveSecret(context.Context, string) (string, error)
}

type SecretResolverFunc func(context.Context, string) (string, error)

func (f SecretResolverFunc) ResolveSecret(ctx context.Context, ref string) (string, error) {
	return f(ctx, ref)
}

type RuntimeConfig struct {
	Manifest       connector.Manifest
	SecretResolver SecretResolver
}

type Runtime struct {
	manifest       connector.Manifest
	secretResolver SecretResolver
}

func New(config RuntimeConfig) *Runtime {
	return &Runtime{
		manifest:       config.Manifest,
		secretResolver: config.SecretResolver,
	}
}

func (r *Runtime) Execute(ctx context.Context, req Request) (Result, error) {
	resource, ok := r.resource(req.Resource)
	if !ok {
		return Result{}, ErrUndeclaredResource
	}
	if !operationExists(resource, req.Operation) {
		return Result{}, ErrOperationNotFound
	}
	if err := validateFields(resource, req.Fields); err != nil {
		return Result{}, err
	}
	if req.Action == ActionWrite && resource.IsReadOnly() {
		return Result{}, ErrReadOnlyResource
	}

	credentialResolved := false
	if req.CredentialRef != "" && r.secretResolver != nil {
		if _, err := r.secretResolver.ResolveSecret(ctx, req.CredentialRef); err != nil {
			return Result{}, err
		}
		credentialResolved = true
	}

	adapter := adapterFor(resource)
	data, err := adapter.Execute(ctx, resource, req)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Resource: resource.Name,
		Adapter:  adapter.Name(),
		Data:     data,
		Audit: AuditContext{
			Resource:           resource.Name,
			Operation:          req.Operation,
			Action:             req.Action,
			Fields:             append([]string(nil), req.Fields...),
			CredentialResolved: credentialResolved,
		},
	}, nil
}

func (r *Runtime) resource(name string) (connector.Resource, bool) {
	for _, resource := range r.manifest.Resources {
		if resource.Name == name {
			return resource, true
		}
	}
	return connector.Resource{}, false
}

func operationExists(resource connector.Resource, name string) bool {
	for _, operation := range resource.Operations {
		if operation.Name == name {
			return true
		}
	}
	return false
}

func validateFields(resource connector.Resource, fields []string) error {
	declared := map[string]struct{}{}
	for _, field := range resource.Fields {
		declared[field.Name] = struct{}{}
	}
	for _, field := range fields {
		if _, ok := declared[field]; !ok {
			return fmt.Errorf("%w: %s.%s", ErrUndeclaredField, resource.Name, field)
		}
	}
	return nil
}

type adapter interface {
	Name() string
	Execute(context.Context, connector.Resource, Request) (map[string]any, error)
}

func adapterFor(resource connector.Resource) adapter {
	switch resource.Type {
	case connector.ResourceTypeDB:
		return dbReadonlyAdapter{}
	case connector.ResourceTypeFile:
		return fileStorageAdapter{}
	default:
		return httpOpenAPIAdapter{}
	}
}
