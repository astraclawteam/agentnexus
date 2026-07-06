package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

const MaskedValue = "***MASKED***"

type Action string

const (
	ActionRead  Action = "read"
	ActionWrite Action = "write"
)

var (
	ErrUndeclaredResource   = errors.New("undeclared connector resource")
	ErrUndeclaredField      = errors.New("undeclared connector field")
	ErrReadOnlyResource     = errors.New("read-only connector resource")
	ErrOperationNotFound    = errors.New("connector operation not found")
	ErrOutputSchemaRequired = errors.New("connector output schema is required")
	ErrRateLimited          = errors.New("connector rate limit exceeded")
)

type Request struct {
	ConnectorInstanceID string
	Resource            string
	Operation           string
	Action              Action
	Fields              []string
	MaskFields          []string
	CredentialRef       string
}

type Result struct {
	Resource string
	Adapter  string
	Data     map[string]any
	Audit    AuditContext
}

type AuditContext struct {
	ConnectorInstanceID string
	Resource            string
	Adapter             string
	Operation           string
	Action              Action
	Fields              []string
	MaskFields          []string
	CredentialResolved  bool
	Attempts            int
	Latency             time.Duration
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
	RateLimiter    *RateLimiter
	Timeout        time.Duration
	MaxRetries     int
	AdapterFactory func(connector.Resource) Adapter
	AuditSink      ConnectorAuditSink
	HealthSink     ConnectorHealthSink
}

type Runtime struct {
	manifest       connector.Manifest
	secretResolver SecretResolver
	rateLimiter    *RateLimiter
	timeout        time.Duration
	maxRetries     int
	adapterFactory func(connector.Resource) Adapter
	auditSink      ConnectorAuditSink
	healthSink     ConnectorHealthSink
}

func New(config RuntimeConfig) *Runtime {
	adapterFactory := config.AdapterFactory
	if adapterFactory == nil {
		adapterFactory = adapterFor
	}
	return &Runtime{
		manifest:       config.Manifest,
		secretResolver: config.SecretResolver,
		rateLimiter:    config.RateLimiter,
		timeout:        config.Timeout,
		maxRetries:     config.MaxRetries,
		adapterFactory: adapterFactory,
		auditSink:      config.AuditSink,
		healthSink:     config.HealthSink,
	}
}

func (r *Runtime) Execute(ctx context.Context, req Request) (result Result, err error) {
	startedAt := time.Now()
	attempts := 0
	decision := "deny"
	defer func() {
		latency := time.Since(startedAt)
		if latency <= 0 {
			latency = time.Nanosecond
		}
		if result.Audit.Resource == "" {
			result.Audit = auditContextFromRequest(req, false, attempts, latency)
		}
		result.Audit.Attempts = attempts
		result.Audit.Latency = latency
		if err == nil {
			decision = "allow"
		}
		if emitErr := r.emitEvents(ctx, req, result.Audit, decision, latency, err); emitErr != nil && err == nil {
			err = emitErr
		}
	}()

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
	if err := validateFields(resource, req.MaskFields); err != nil {
		return Result{}, err
	}
	if req.Action == ActionWrite && resource.IsReadOnly() {
		return Result{}, ErrReadOnlyResource
	}
	if !ValidateOutputSchema(resource) {
		return Result{}, ErrOutputSchemaRequired
	}
	if r.rateLimiter != nil && !r.rateLimiter.Allow(rateLimitKey(req)) {
		return Result{}, ErrRateLimited
	}

	credentialResolved := false
	if req.CredentialRef != "" && r.secretResolver != nil {
		if _, err := r.secretResolver.ResolveSecret(ctx, req.CredentialRef); err != nil {
			return Result{}, err
		}
		credentialResolved = true
	}

	adapter := r.adapterFactory(resource)
	data, err := r.executeAdapter(ctx, adapter, resource, req, &attempts)
	if err != nil {
		return Result{}, err
	}
	data = maskData(data, req.MaskFields)

	return Result{
		Resource: resource.Name,
		Adapter:  adapter.Name(),
		Data:     data,
		Audit: AuditContext{
			ConnectorInstanceID: req.ConnectorInstanceID,
			Resource:            resource.Name,
			Adapter:             adapter.Name(),
			Operation:           req.Operation,
			Action:              req.Action,
			Fields:              append([]string(nil), req.Fields...),
			MaskFields:          append([]string(nil), req.MaskFields...),
			CredentialResolved:  credentialResolved,
			Attempts:            attempts,
			Latency:             time.Since(startedAt),
		},
	}, nil
}

func (r *Runtime) executeAdapter(ctx context.Context, adapter Adapter, resource connector.Resource, req Request, attempts *int) (map[string]any, error) {
	maxAttempts := 1 + r.maxRetries
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	var lastErr error
	for *attempts < maxAttempts {
		*attempts++
		attemptCtx := ctx
		cancel := func() {}
		if r.timeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, r.timeout)
		}
		data, err := adapter.Execute(attemptCtx, resource, req)
		cancel()
		if err == nil {
			return data, nil
		}
		lastErr = err
	}
	return nil, lastErr
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

type Adapter interface {
	Name() string
	Execute(context.Context, connector.Resource, Request) (map[string]any, error)
}

func adapterFor(resource connector.Resource) Adapter {
	switch resource.Type {
	case connector.ResourceTypeDB:
		return dbReadonlyAdapter{}
	case connector.ResourceTypeFile:
		return fileStorageAdapter{}
	default:
		return httpOpenAPIAdapter{}
	}
}

type ConnectorAuditSink interface {
	RecordConnectorAudit(context.Context, ConnectorAuditEvent) error
}

type ConnectorHealthSink interface {
	RecordConnectorHealth(context.Context, ConnectorHealthEvent) error
}

type ConnectorAuditEvent struct {
	ConnectorInstanceID string
	Resource            string
	Operation           string
	Action              Action
	Decision            string
	Fields              []string
	MaskFields          []string
	CredentialResolved  bool
	Attempts            int
	Latency             time.Duration
	Error               string
}

type ConnectorHealthEvent struct {
	ConnectorInstanceID string
	Resource            string
	Operation           string
	Adapter             string
	OK                  bool
	Attempts            int
	Latency             time.Duration
	Error               string
}

func (r *Runtime) emitEvents(ctx context.Context, req Request, audit AuditContext, decision string, latency time.Duration, execErr error) error {
	errText := ""
	if execErr != nil {
		errText = execErr.Error()
	}
	if r.auditSink != nil {
		if err := r.auditSink.RecordConnectorAudit(ctx, ConnectorAuditEvent{
			ConnectorInstanceID: audit.ConnectorInstanceID,
			Resource:            req.Resource,
			Operation:           req.Operation,
			Action:              req.Action,
			Decision:            decision,
			Fields:              append([]string(nil), req.Fields...),
			MaskFields:          append([]string(nil), req.MaskFields...),
			CredentialResolved:  audit.CredentialResolved,
			Attempts:            audit.Attempts,
			Latency:             latency,
			Error:               errText,
		}); err != nil {
			return err
		}
	}
	if r.healthSink != nil {
		if err := r.healthSink.RecordConnectorHealth(ctx, ConnectorHealthEvent{
			ConnectorInstanceID: audit.ConnectorInstanceID,
			Resource:            req.Resource,
			Operation:           req.Operation,
			Adapter:             audit.Adapter,
			OK:                  execErr == nil,
			Attempts:            audit.Attempts,
			Latency:             latency,
			Error:               errText,
		}); err != nil {
			return err
		}
	}
	return nil
}

func auditContextFromRequest(req Request, credentialResolved bool, attempts int, latency time.Duration) AuditContext {
	return AuditContext{
		ConnectorInstanceID: req.ConnectorInstanceID,
		Resource:            req.Resource,
		Adapter:             "",
		Operation:           req.Operation,
		Action:              req.Action,
		Fields:              append([]string(nil), req.Fields...),
		MaskFields:          append([]string(nil), req.MaskFields...),
		CredentialResolved:  credentialResolved,
		Attempts:            attempts,
		Latency:             latency,
	}
}

func rateLimitKey(req Request) string {
	if req.ConnectorInstanceID != "" {
		return req.ConnectorInstanceID
	}
	return req.Resource
}

func maskData(data map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return data
	}
	result := make(map[string]any, len(data))
	for key, value := range data {
		result[key] = value
	}
	for _, field := range fields {
		if _, ok := result[field]; ok {
			result[field] = MaskedValue
		}
	}
	return result
}
