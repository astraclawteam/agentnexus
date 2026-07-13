package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
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
	// ErrNoSecretProvider marks a request that references a credential while no
	// secret provider (nor the legacy resolver) is configured. The runtime fails
	// closed rather than silently proceeding without resolving the credential.
	ErrNoSecretProvider = errors.New("connector requires a credential but no secret provider is configured")
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
	// Secret Handle facts. These are non-secret metadata only: the opaque
	// handle id, the master version it derives from, its operation scope and
	// its lifetime. A master credential is never among them.
	HandleID        string
	HandleVersion   string
	HandleScope     string
	HandleSingleUse bool
	HandleExpiresAt time.Time
}

// SecretHandleProvider is the connector runtime's secret port. It yields an
// operation-scoped, short-lived Secret Handle for a credential reference and a
// scope; it never yields a master credential. A provider outage surfaces as an
// error so the runtime fails closed. internal/secrets.Client satisfies it.
type SecretHandleProvider interface {
	AcquireHandle(ctx context.Context, scope secretprovider.Scope, credentialRef string) (secretprovider.Handle, error)
}

// SecretResolver is the legacy opaque-credential-reference resolver retained
// for the pre-GA scaffolding path used by existing local fixtures. When a
// SecretHandleProvider is configured it is the sole GA credential mechanism and
// this resolver is not consulted; production readiness (internal/secrets) fails
// closed without a provider, so the legacy path never runs in production.
type SecretResolver interface {
	ResolveSecret(context.Context, string) (string, error)
}

type SecretResolverFunc func(context.Context, string) (string, error)

func (f SecretResolverFunc) ResolveSecret(ctx context.Context, ref string) (string, error) {
	return f(ctx, ref)
}

type RuntimeConfig struct {
	Manifest connector.Manifest
	// SecretHandles is the GA secret-handle provider. When set, the runtime
	// acquires an operation-scoped Secret Handle instead of resolving a master.
	SecretHandles SecretHandleProvider
	// SecretResolver is the legacy opaque-reference resolver (see SecretResolver).
	SecretResolver SecretResolver
}

type Runtime struct {
	manifest       connector.Manifest
	secretHandles  SecretHandleProvider
	secretResolver SecretResolver
}

func New(config RuntimeConfig) *Runtime {
	return &Runtime{
		manifest:       config.Manifest,
		secretHandles:  config.SecretHandles,
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
	var handle secretHandleFacts
	if req.CredentialRef != "" {
		switch {
		case r.secretHandles != nil:
			// GA path: acquire an operation-scoped Secret Handle bound to this
			// connector identity and operation. The runtime receives only the
			// handle — never a master credential. A provider outage returns an
			// error here, so the operation fails closed with no fallback.
			acquired, err := r.secretHandles.AcquireHandle(ctx, secretprovider.Scope{
				ConnectorRef: r.manifest.Name,
				Resource:     req.Resource,
				Operation:    req.Operation,
				Action:       string(req.Action),
			}, req.CredentialRef)
			if err != nil {
				return Result{}, err
			}
			credentialResolved = true
			handle = secretHandleFacts{
				id:        acquired.ID(),
				version:   acquired.Version(),
				scope:     acquired.Scope().String(),
				singleUse: acquired.SingleUse(),
				expiresAt: acquired.ExpiresAt(),
			}
		case r.secretResolver != nil:
			// Legacy scaffolding path (see SecretResolver): opaque-reference
			// resolution whose value is never placed in the result or audit.
			if _, err := r.secretResolver.ResolveSecret(ctx, req.CredentialRef); err != nil {
				return Result{}, err
			}
			credentialResolved = true
		default:
			// Invariant: a credential is required but nothing can resolve it.
			// Fail closed so a future adapter that consumes material can never
			// run against an unresolved credential.
			return Result{}, ErrNoSecretProvider
		}
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
			HandleID:           handle.id,
			HandleVersion:      handle.version,
			HandleScope:        handle.scope,
			HandleSingleUse:    handle.singleUse,
			HandleExpiresAt:    handle.expiresAt,
		},
	}, nil
}

// secretHandleFacts carries the non-secret audit facts of an acquired Secret
// Handle from acquisition to the audit record.
type secretHandleFacts struct {
	id        string
	version   string
	scope     string
	singleUse bool
	expiresAt time.Time
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
