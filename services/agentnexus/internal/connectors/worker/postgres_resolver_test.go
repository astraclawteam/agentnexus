package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

// The PostgresBindingResolver is tested against REAL PostgreSQL. Almost
// everything it does is SQL — the tenant predicate, the digest-tuple join to the
// signed product, and the "more than one binding" ambiguity — and a fake store
// would assert only that the fake behaves like the fake. The one test that
// genuinely does not need a database (a nil pool) is separate, below.
//
// DSN-gated on the evidence-suite pattern: these skip cleanly where no
// PostgreSQL is available.
//
// WARNING: the target database is mutated (the fixture drops and recreates the
// connector_products/connector_bindings tables). Point
// AGENTNEXUS_E2E_POSTGRES_DSN at a disposable database.

const (
	resolverTenant     = "ten_resolver"
	resolverCapability = "httpapi.orders.read"
	resolverResource   = "erp_orders_internal_tbl"
	resolverCredential = "secretref://vault/acme/connector"
	resolverBindingKey = "acme-orders"
)

func resolverPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTNEXUS_E2E_POSTGRES_DSN")
	if dsn == "" {
		dsn = os.Getenv("AGENTNEXUS_POSTGRES_DSN")
	}
	if dsn == "" {
		t.Skip("set AGENTNEXUS_E2E_POSTGRES_DSN (or AGENTNEXUS_POSTGRES_DSN) to run the binding resolver integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// gooseBlock extracts one direction's statement block from migration 000012.
func resolverGooseBlock(t *testing.T, direction string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "db", "migrations", "000012_connector_products_bindings.sql"))
	if err != nil {
		t.Fatalf("read migration 000012: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "-- +goose "+direction)
	if start < 0 {
		t.Fatalf("migration 000012 is missing the %s marker", direction)
	}
	segment := text[start:]
	begin := strings.Index(segment, "-- +goose StatementBegin")
	end := strings.Index(segment, "-- +goose StatementEnd")
	if begin < 0 || end < 0 || end < begin {
		t.Fatalf("migration 000012 %s block is malformed", direction)
	}
	return segment[begin+len("-- +goose StatementBegin") : end]
}

func newResolverFixture(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := resolverPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, resolverGooseBlock(t, "Down")); err != nil {
		t.Fatalf("migration 000012 down (pre-clean): %v", err)
	}
	if _, err := pool.Exec(ctx, resolverGooseBlock(t, "Up")); err != nil {
		t.Fatalf("migration 000012 up: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), resolverGooseBlock(t, "Down"))
		pool.Close()
	})
	return pool
}

// productionPack loads the development fixture and promotes it to the signed
// production form the tables and ImportProductionPack require: development
// cleared, SBOM/provenance/signature present, and the content digest recomputed
// LAST so it binds the finished document.
//
// Honest scope note, carried from the SDK: ImportProductionPack verifies the
// signature's STRUCTURE and the content-digest binding, not its authenticity
// against a trusted key (that is the connector certification / key-management
// task). So this fixture's signature is well-formed, not trusted — which is
// exactly what the code under test checks.
func productionPack(t *testing.T) connector.ProductPack {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "connectors", "http-openapi-pack.yaml"))
	if err != nil {
		t.Fatalf("read pack fixture: %v", err)
	}
	// yaml -> map -> json: the SDK structs are json-tagged only, so unmarshaling
	// the YAML straight into them would silently miss every field.
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("yaml unmarshal pack: %v", err)
	}
	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("json marshal pack: %v", err)
	}
	pack, err := connector.ParseProductPack(jsonBytes)
	if err != nil {
		t.Fatalf("ParseProductPack: %v", err)
	}
	pack.Development = false
	const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	pack.SBOM = connector.ArtifactRef{Ref: "sbom.httpapi.orders.catalog", Digest: zeroDigest}
	pack.Provenance = connector.ArtifactRef{Ref: "provenance.httpapi.orders.catalog", Digest: zeroDigest}
	pack.Signature = connector.Signature{
		Algorithm: "ed25519",
		KeyID:     "test-key-1",
		Value:     "dGVzdC1zaWduYXR1cmUtdmFsdWU=",
	}
	pack.Digest = connector.PackContentDigest(pack)
	if _, err := connector.ImportProductionPack(mustJSON(t, pack)); err != nil {
		t.Fatalf("the promoted fixture is not an importable production pack: %v", err)
	}
	return pack
}

func customerBinding(pack connector.ProductPack, bindingKey string) connector.CustomerBinding {
	return connector.CustomerBinding{
		SchemaVersion: connector.CustomerBindingSchemaVersion,
		BindingKey:    bindingKey,
		Customer:      connector.CustomerRef{Name: "acme"},
		Product: connector.ProductRef{
			ProductKey: pack.ProductKey, Version: pack.Version, Digest: pack.Digest,
		},
		Endpoints:        []connector.Endpoint{{Name: "api", URL: "https://orders.acme.internal:8443/v2"}},
		Secrets:          []connector.SecretRef{{Name: "connector-token", Ref: resolverCredential}},
		ResourceMappings: []connector.ResourceMapping{{Capability: resolverCapability, Resource: resolverResource}},
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func seedProduct(t *testing.T, pool *pgxpool.Pool, tenant string, pack connector.ProductPack) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO connector_products (tenant_id, product_key, version, digest, signature_algorithm,
			signature_key_id, signature_value, sbom_digest, provenance_digest, pack_document)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		tenant, pack.ProductKey, pack.Version, pack.Digest, pack.Signature.Algorithm,
		pack.Signature.KeyID, pack.Signature.Value, pack.SBOM.Digest, pack.Provenance.Digest,
		mustJSON(t, pack))
	if err != nil {
		t.Fatalf("seed product: %v", err)
	}
}

func seedBinding(t *testing.T, pool *pgxpool.Pool, tenant string, binding connector.CustomerBinding) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO connector_bindings (tenant_id, binding_key, product_key, product_version,
			product_digest, binding_document)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		tenant, binding.BindingKey, binding.Product.ProductKey, binding.Product.Version,
		binding.Product.Digest, mustJSON(t, binding))
	if err != nil {
		t.Fatalf("seed binding: %v", err)
	}
}

// recordingFactory stands in for the connector-family wiring this build does
// not have. It records what server-side truth the resolver handed it — which is
// the contract that matters, since a factory must not be able to widen a
// resolution — and returns the package's existing host fake rather than a second
// stub that would be free to drift from the HostRunner interface.
type recordingFactory struct {
	got ResolutionRequest
	err error
}

func (f *recordingFactory) HostFor(_ context.Context, req ResolutionRequest) (HostBinding, error) {
	f.got = req
	if f.err != nil {
		return HostBinding{}, f.err
	}
	return HostBinding{Host: &fakeHost{}, Operation: "list"}, nil
}

func TestPostgresResolverResolvesCoordinatesFromThePinnedPackAndBinding(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	seedBinding(t, pool, resolverTenant, customerBinding(pack, resolverBindingKey))

	factory := &recordingFactory{}
	resolved, err := NewPostgresBindingResolver(pool, factory).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Resource != resolverResource {
		t.Errorf("Resource = %q, want the binding's mapped resource %q", resolved.Resource, resolverResource)
	}
	// "read" comes from the PACK capability's declared effect, never from a
	// caller: a resolver that took it from the request would let a read
	// capability be executed as a write.
	if resolved.OperationAction != "read" {
		t.Errorf("OperationAction = %q, want read (the pack capability's effect)", resolved.OperationAction)
	}
	if resolved.CredentialRef != resolverCredential {
		t.Errorf("CredentialRef = %q, want the binding's secret reference %q", resolved.CredentialRef, resolverCredential)
	}
	if resolved.Operation != "list" {
		t.Errorf("Operation = %q, want the factory-supplied verb", resolved.Operation)
	}
	if resolved.ConnectorRef != resolverBindingKey {
		t.Errorf("ConnectorRef = %q, want the private binding key %q", resolved.ConnectorRef, resolverBindingKey)
	}
	if resolved.Host == nil {
		t.Error("resolved binding has no host runner")
	}
	// The factory receives server-side truth, so it cannot widen the resolution.
	if factory.got.Resource != resolverResource || factory.got.OperationAction != "read" ||
		factory.got.Pack.Digest != pack.Digest || factory.got.TenantRef != resolverTenant {
		t.Errorf("the factory was handed %+v, want the resolved server-side coordinates", factory.got)
	}
}

// Cross-tenant isolation through the REAL SQL predicate. A dropped tenant_id
// clause would surface here and nowhere else.
func TestPostgresResolverNeverCrossesTenants(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	seedBinding(t, pool, resolverTenant, customerBinding(pack, resolverBindingKey))

	_, err := NewPostgresBindingResolver(pool, &recordingFactory{}).
		Resolve(context.Background(), "ten_someone_else", resolverCapability)
	if !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("another tenant's binding must be invisible, got %v", err)
	}
}

func TestPostgresResolverFailsClosedOnAnUnknownCapability(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	seedBinding(t, pool, resolverTenant, customerBinding(pack, resolverBindingKey))

	_, err := NewPostgresBindingResolver(pool, &recordingFactory{}).
		Resolve(context.Background(), resolverTenant, "httpapi.orders.delete")
	if !errors.Is(err, ErrBindingNotFound) {
		t.Fatalf("an undeclared capability must fail closed, got %v", err)
	}
}

// Two bindings declaring the same capability is a REFUSAL, not a choice.
// Executing either would commit a real side effect against an arbitrary
// customer system picked by sort order.
func TestPostgresResolverRefusesAnAmbiguousBinding(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	seedBinding(t, pool, resolverTenant, customerBinding(pack, "acme-orders-a"))
	seedBinding(t, pool, resolverTenant, customerBinding(pack, "acme-orders-b"))

	factory := &recordingFactory{}
	_, err := NewPostgresBindingResolver(pool, factory).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if !errors.Is(err, ErrBindingAmbiguous) {
		t.Fatalf("two bindings for one capability must be refused, got %v", err)
	}
	// The refusal must happen BEFORE a host is built: an ambiguous binding that
	// still reached the factory would already have picked one.
	if factory.got.Capability != "" {
		t.Errorf("the factory was consulted for an ambiguous binding: %+v", factory.got)
	}
}

// A binding whose DOCUMENT pins a digest other than the pack it loaded. The
// foreign key cannot catch this: it constrains the table's columns to each
// other, and both columns here are consistent — it is the binding_document that
// disagrees. The documents are the authority.
func TestPostgresResolverRefusesADigestSwappedBinding(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)

	binding := customerBinding(pack, resolverBindingKey)
	stored := binding
	// The COLUMNS still reference the real product (so the FK is satisfied);
	// only the document's pinned digest is swapped.
	binding.Product.Digest = "sha256:" + strings.Repeat("a", 64)
	_, err := pool.Exec(context.Background(), `
		INSERT INTO connector_bindings (tenant_id, binding_key, product_key, product_version,
			product_digest, binding_document)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		resolverTenant, stored.BindingKey, stored.Product.ProductKey, stored.Product.Version,
		stored.Product.Digest, mustJSON(t, binding))
	if err != nil {
		t.Fatalf("seed digest-swapped binding: %v", err)
	}

	_, resolveErr := NewPostgresBindingResolver(pool, &recordingFactory{}).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if !errors.Is(resolveErr, ErrBindingUnresolvable) {
		t.Fatalf("a digest-swapped binding must be refused, got %v", resolveErr)
	}
	if !strings.Contains(resolveErr.Error(), "digest") {
		t.Errorf("the refusal must name the digest mismatch, got %v", resolveErr)
	}
}

func TestPostgresResolverRefusesACapabilityWithNoResourceMapping(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	binding := customerBinding(pack, resolverBindingKey)
	binding.ResourceMappings = nil
	seedBinding(t, pool, resolverTenant, binding)

	_, err := NewPostgresBindingResolver(pool, &recordingFactory{}).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if !errors.Is(err, ErrBindingUnresolvable) {
		t.Fatalf("an unmapped capability must be refused, got %v", err)
	}
}

// Several secrets and no declared rule for choosing among them. Taking the
// first would bind a real side effect to whichever secret was listed first.
func TestPostgresResolverRefusesAnAmbiguousCredential(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	binding := customerBinding(pack, resolverBindingKey)
	binding.Secrets = append(binding.Secrets, connector.SecretRef{Name: "second", Ref: "secretref://vault/acme/other"})
	seedBinding(t, pool, resolverTenant, binding)

	_, err := NewPostgresBindingResolver(pool, &recordingFactory{}).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if !errors.Is(err, ErrBindingUnresolvable) {
		t.Fatalf("an ambiguous credential must be refused, got %v", err)
	}
}

// The shipped state of this build: no HostFactory, because no connector family
// has a production client. The failure must be ErrNoHostFactory — a NAMED
// deployment fact — and it must come only after the binding itself resolved, so
// an operator is not told "no host factory" about a binding that is also broken.
func TestPostgresResolverWithoutAHostFactoryFailsClosedWithANamedReason(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	seedBinding(t, pool, resolverTenant, customerBinding(pack, resolverBindingKey))

	resolved, err := NewPostgresBindingResolver(pool, nil).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if !errors.Is(err, ErrNoHostFactory) {
		t.Fatalf("a resolver with no host factory must fail closed at ErrNoHostFactory, got %v", err)
	}
	// Nothing fabricated on the way out.
	if resolved.Host != nil || resolved.Resource != "" || resolved.CredentialRef != "" {
		t.Errorf("a failed resolution must return the zero binding, got %+v", resolved)
	}

	// A BROKEN binding under the same nil factory must still report what is
	// broken. If ErrNoHostFactory short-circuited first, every real binding
	// defect would be masked by the missing-host message.
	broken := customerBinding(pack, "acme-unmapped")
	broken.ResourceMappings = nil
	seedBinding(t, pool, resolverTenant, broken)
	_, err = NewPostgresBindingResolver(pool, nil).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if errors.Is(err, ErrNoHostFactory) {
		t.Fatalf("a broken binding was reported as a missing host factory: %v", err)
	}
}

// A factory that refuses must not be turned into a runnable binding.
func TestPostgresResolverPropagatesAHostFactoryRefusal(t *testing.T) {
	pool := newResolverFixture(t)
	pack := productionPack(t)
	seedProduct(t, pool, resolverTenant, pack)
	seedBinding(t, pool, resolverTenant, customerBinding(pack, resolverBindingKey))

	refusal := errors.New("no family adapter for this product")
	resolved, err := NewPostgresBindingResolver(pool, &recordingFactory{err: refusal}).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if !errors.Is(err, refusal) {
		t.Fatalf("Resolve must surface the factory's refusal, got %v", err)
	}
	if resolved.Host != nil {
		t.Error("a refused factory must not yield a host")
	}
}

// The one case that needs no database.
func TestPostgresResolverWithoutAPoolIsNotReady(t *testing.T) {
	_, err := NewPostgresBindingResolver(nil, &recordingFactory{}).
		Resolve(context.Background(), resolverTenant, resolverCapability)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("a resolver with no pool must report not-ready, got %v", err)
	}
}
