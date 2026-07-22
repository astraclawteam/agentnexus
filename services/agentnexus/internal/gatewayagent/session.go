package gatewayagent

import (
	"context"
	"errors"
	"fmt"

	adksession "google.golang.org/adk/v2/session"
)

// tenantKey carries the verified tenant through the ADK call chain.
//
// It is a context value rather than a parameter because ADK owns the call path
// between Runner.Run and the session service: there is no seam to thread an
// argument through. It is deliberately NOT reachable from an LLM argument or a
// tool payload - the tenant is established once at the service edge from the
// verified browser session and is never something a model can influence.
type tenantKey struct{}

// ErrNoTenant is returned when a tenant-scoped operation runs on a context that
// carries no tenant.
var ErrNoTenant = errors.New("gateway agent: no tenant in context")

// ErrTenantMismatch is returned when an operation carries a session that
// belongs to a different tenant than the one bound to the context.
var ErrTenantMismatch = errors.New("gateway agent: session belongs to another tenant")

// WithTenant binds the verified tenant to ctx. Call it at the service edge,
// from the credential-derived trusted context - never from request JSON.
func WithTenant(ctx context.Context, tenantRef string) context.Context {
	return context.WithValue(ctx, tenantKey{}, tenantRef)
}

// TenantFrom reads the verified tenant back out.
func TenantFrom(ctx context.Context) (string, error) {
	tenantRef, _ := ctx.Value(tenantKey{}).(string)
	if tenantRef == "" {
		return "", ErrNoTenant
	}
	return tenantRef, nil
}

// TenantScopedSessionService namespaces ADK's session key space by tenant.
//
// ADK addresses a session by (AppName, UserID, SessionID) and none of those is
// a tenant. Two tenants using the same operator identifier and session
// identifier would otherwise share one conversation, including whatever the
// assistant learned about the other tenant's environment.
//
// This decorator authors AppName itself, from the app name and the verified
// tenant. A caller-supplied AppName is DISCARDED rather than merged: accepting
// it would let a caller name another tenant's namespace and walk straight into
// it. Scoping by AppName rather than by UserID keeps UserID meaning what it
// says - the operator - instead of turning it into a compound key.
type TenantScopedSessionService struct {
	inner   adksession.Service
	appName string
}

var _ adksession.Service = (*TenantScopedSessionService)(nil)

// NewTenantScopedSessionService wraps an ADK session service.
func NewTenantScopedSessionService(inner adksession.Service, appName string) *TenantScopedSessionService {
	return &TenantScopedSessionService{inner: inner, appName: appName}
}

// scope derives the tenant-namespaced app name. Every method funnels through
// it, so a new session operation cannot accidentally skip the boundary.
func (s *TenantScopedSessionService) scope(ctx context.Context) (string, error) {
	if s == nil || s.inner == nil {
		return "", errors.New("gateway agent: session service unavailable")
	}
	tenantRef, err := TenantFrom(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s", s.appName, tenantRef), nil
}

// ScopedAppName exposes the namespaced app name so the runner can address the
// same key space ADK will use. It fails closed exactly like the store methods.
func (s *TenantScopedSessionService) ScopedAppName(ctx context.Context) (string, error) {
	return s.scope(ctx)
}

func (s *TenantScopedSessionService) Create(ctx context.Context, req *adksession.CreateRequest) (*adksession.CreateResponse, error) {
	appName, err := s.scope(ctx)
	if err != nil {
		return nil, err
	}
	scoped := *req
	scoped.AppName = appName
	return s.inner.Create(ctx, &scoped)
}

func (s *TenantScopedSessionService) Get(ctx context.Context, req *adksession.GetRequest) (*adksession.GetResponse, error) {
	appName, err := s.scope(ctx)
	if err != nil {
		return nil, err
	}
	scoped := *req
	scoped.AppName = appName
	return s.inner.Get(ctx, &scoped)
}

func (s *TenantScopedSessionService) List(ctx context.Context, req *adksession.ListRequest) (*adksession.ListResponse, error) {
	appName, err := s.scope(ctx)
	if err != nil {
		return nil, err
	}
	scoped := *req
	scoped.AppName = appName
	return s.inner.List(ctx, &scoped)
}

func (s *TenantScopedSessionService) Delete(ctx context.Context, req *adksession.DeleteRequest) error {
	appName, err := s.scope(ctx)
	if err != nil {
		return err
	}
	scoped := *req
	scoped.AppName = appName
	return s.inner.Delete(ctx, &scoped)
}

// AppendEvent carries the session itself rather than a request struct, and
// adksession.Session exposes AppName only as a read-only accessor. There is
// therefore no field to re-author: the scope is VALIDATED here instead.
//
// Validating is not a weaker substitute for re-authoring, it is the only thing
// that holds the boundary on this path. The inner service keys the append by
// the session's own AppName, so a session opened under one tenant has its
// events written into that tenant's namespace no matter which tenant ctx
// carries. Checking only that SOME tenant is present would let a caller append
// into a namespace its credential never proved - a cross-tenant write.
func (s *TenantScopedSessionService) AppendEvent(ctx context.Context, sess adksession.Session, event *adksession.Event) error {
	appName, err := s.scope(ctx)
	if err != nil {
		return err
	}
	if sess == nil {
		return errors.New("gateway agent: append to a nil session")
	}
	if sess.AppName() != appName {
		// The session's own AppName is deliberately not echoed: the caller
		// already knows the scope it is entitled to, and naming the other
		// tenant's namespace in an error is itself a small disclosure.
		return fmt.Errorf("%w: expected namespace %q", ErrTenantMismatch, appName)
	}
	return s.inner.AppendEvent(ctx, sess, event)
}
