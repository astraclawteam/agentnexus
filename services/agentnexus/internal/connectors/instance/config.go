package instance

import (
	"context"
	"fmt"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/manifest"
	connectorruntime "github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/runtime"
)

const (
	StatusDraft     = "draft"
	StatusPublished = "published"
)

type Package struct {
	ID        string
	Name      string
	Version   string
	Manifest  connector.Manifest
	CreatedAt time.Time
}

type Config struct {
	ID             string
	EnterpriseID   string
	PackageID      string
	PackageName    string
	BaseURL        string
	AccountSet     []string
	FieldMapping   map[string]string
	DataScope      []string
	CredentialRefs map[string]string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type DraftInstanceInput struct {
	EnterpriseID   string
	Manifest       connector.Manifest
	BaseURL        string
	AccountSet     []string
	FieldMapping   map[string]string
	DataScope      []string
	CredentialRefs map[string]string
}

type DraftInstanceResult struct {
	Package  Package
	Instance Config
}

type SmokeInstanceInput struct {
	EnterpriseID string
	InstanceID   string
	Resource     string
	Operation    string
	Fields       []string
}

type SmokeInstanceResult struct {
	OK                 bool
	Adapter            string
	CredentialResolved bool
	SchemaValid        bool
	MaskingValid       bool
	AuditEventID       string
}

type ConfirmInstanceInput struct {
	EnterpriseID        string
	InstanceID          string
	HumanConfirmationID string
}

type Store interface {
	CreatePackage(context.Context, Package) (Package, error)
	CreateInstance(context.Context, Config) (Config, error)
	GetPackage(context.Context, string) (Package, error)
	GetInstance(context.Context, string, string) (Config, error)
	UpdateInstanceStatus(context.Context, string, string, string) (Config, error)
}

type SecretResolver interface {
	ResolveSecret(context.Context, string) (string, error)
}

type StaticSecretResolver map[string]string

func (r StaticSecretResolver) ResolveSecret(_ context.Context, ref string) (string, error) {
	value, ok := r[ref]
	if !ok {
		return "", fmt.Errorf("secret ref %q not found", ref)
	}
	return value, nil
}

type AuditSink interface {
	AppendConnectorAudit(context.Context, ConnectorAuditEvent) (ConnectorAuditEvent, error)
}

type ConnectorAuditEvent struct {
	ID           string
	EnterpriseID string
	InstanceID   string
	Resource     string
	Operation    string
	Decision     string
	CreatedAt    time.Time
}

type ServiceConfig struct {
	SecretResolver SecretResolver
	AuditSink      AuditSink
	NewID          func() string
}

type Service struct {
	store          Store
	secretResolver SecretResolver
	auditSink      AuditSink
	newID          func() string
	now            func() time.Time
}

func NewService(store Store, cfg ServiceConfig) *Service {
	newID := cfg.NewID
	if newID == nil {
		newID = func() string { return "generated_id" }
	}
	return &Service{
		store:          store,
		secretResolver: cfg.SecretResolver,
		auditSink:      cfg.AuditSink,
		newID:          newID,
		now:            func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) DraftInstance(ctx context.Context, input DraftInstanceInput) (DraftInstanceResult, error) {
	if err := manifest.Validate(input.Manifest); err != nil {
		return DraftInstanceResult{}, err
	}
	pkg, err := s.store.CreatePackage(ctx, Package{
		ID:        s.newID(),
		Name:      input.Manifest.Name,
		Version:   input.Manifest.Version,
		Manifest:  input.Manifest,
		CreatedAt: s.now(),
	})
	if err != nil {
		return DraftInstanceResult{}, err
	}
	instance, err := s.store.CreateInstance(ctx, Config{
		ID:             s.newID(),
		EnterpriseID:   input.EnterpriseID,
		PackageID:      pkg.ID,
		PackageName:    pkg.Name,
		BaseURL:        input.BaseURL,
		AccountSet:     append([]string(nil), input.AccountSet...),
		FieldMapping:   cloneStringMap(input.FieldMapping),
		DataScope:      append([]string(nil), input.DataScope...),
		CredentialRefs: cloneStringMap(input.CredentialRefs),
		Status:         StatusDraft,
		CreatedAt:      s.now(),
		UpdatedAt:      s.now(),
	})
	if err != nil {
		return DraftInstanceResult{}, err
	}
	return DraftInstanceResult{Package: pkg, Instance: instance}, nil
}

func (s *Service) SmokeInstance(ctx context.Context, input SmokeInstanceInput) (SmokeInstanceResult, error) {
	instance, err := s.store.GetInstance(ctx, input.EnterpriseID, input.InstanceID)
	if err != nil {
		return SmokeInstanceResult{}, err
	}
	pkg, err := s.store.GetPackage(ctx, instance.PackageID)
	if err != nil {
		return SmokeInstanceResult{}, err
	}
	credentialRef := credentialRefFor(pkg.Manifest, instance, input.Resource)
	runtime := connectorruntime.New(connectorruntime.RuntimeConfig{
		Manifest:       pkg.Manifest,
		SecretResolver: secretResolverAdapter{s.secretResolver},
	})
	result, err := runtime.Execute(ctx, connectorruntime.Request{
		Resource:      input.Resource,
		Operation:     input.Operation,
		Action:        connectorruntime.ActionRead,
		Fields:        input.Fields,
		CredentialRef: credentialRef,
	})
	if err != nil {
		return SmokeInstanceResult{}, err
	}
	auditID := ""
	if s.auditSink != nil {
		event, err := s.auditSink.AppendConnectorAudit(ctx, ConnectorAuditEvent{
			ID:           s.newID(),
			EnterpriseID: input.EnterpriseID,
			InstanceID:   input.InstanceID,
			Resource:     input.Resource,
			Operation:    input.Operation,
			Decision:     "allow",
			CreatedAt:    s.now(),
		})
		if err != nil {
			return SmokeInstanceResult{}, err
		}
		auditID = event.ID
	}
	return SmokeInstanceResult{
		OK:                 true,
		Adapter:            result.Adapter,
		CredentialResolved: result.Audit.CredentialResolved,
		SchemaValid:        validateOutputSchema(pkg.Manifest, input.Resource),
		MaskingValid:       validateMasking(pkg.Manifest, input.Resource, input.Fields),
		AuditEventID:       auditID,
	}, nil
}

func (s *Service) ConfirmInstance(ctx context.Context, input ConfirmInstanceInput) (Config, error) {
	if input.HumanConfirmationID == "" {
		return Config{}, fmt.Errorf("human_confirmation_id is required")
	}
	return s.store.UpdateInstanceStatus(ctx, input.EnterpriseID, input.InstanceID, StatusPublished)
}

func credentialRefFor(manifest connector.Manifest, instance Config, resourceName string) string {
	for _, credential := range manifest.Credentials {
		if ref := instance.CredentialRefs[credential.Name]; ref != "" {
			return ref
		}
	}
	for _, ref := range instance.CredentialRefs {
		return ref
	}
	return ""
}

func validateOutputSchema(manifest connector.Manifest, resourceName string) bool {
	for _, resource := range manifest.Resources {
		if resource.Name == resourceName {
			return connectorruntime.ValidateOutputSchema(resource)
		}
	}
	return false
}

func validateMasking(manifest connector.Manifest, resourceName string, fields []string) bool {
	for _, resource := range manifest.Resources {
		if resource.Name != resourceName {
			continue
		}
		return connectorruntime.ValidateMasking(resource, fields)
	}
	return false
}

type secretResolverAdapter struct {
	resolver SecretResolver
}

func (a secretResolverAdapter) ResolveSecret(ctx context.Context, ref string) (string, error) {
	if a.resolver == nil {
		return "", nil
	}
	return a.resolver.ResolveSecret(ctx, ref)
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return map[string]string{}
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
