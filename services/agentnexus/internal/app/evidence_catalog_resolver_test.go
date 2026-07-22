package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
)

// The document half of connector-source resolution, tested without a database.
// What is NOT covered here is the single SQL statement in
// postgresConnectorSourceResolver: it is byte-identical to the one
// worker.PostgresBindingResolver already exercises against real PostgreSQL
// (ListConnectorBindingsForCapability), so a fake store here would only assert
// that the fake behaves like the fake.

const (
	resolverTestCapability = "httpapi.orders.read"
	resolverTestBindingKey = "acme-orders"
)

// resolverTestPack promotes the development fixture to the signed production
// form ImportProductionPack requires, following the same recipe as
// worker/postgres_resolver_test.go. The signature is well-formed rather than
// trusted, which is exactly what the code under test checks.
func resolverTestPack(t *testing.T) connector.ProductPack {
	return resolverTestPackFrom(t, "http-openapi-pack.yaml", "sbom.httpapi.orders.catalog", "provenance.httpapi.orders.catalog")
}

func resolverTestPackFrom(t *testing.T, fixture, sbomRef, provenanceRef string) connector.ProductPack {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "connectors", fixture))
	if err != nil {
		t.Fatalf("read pack fixture: %v", err)
	}
	// yaml -> map -> json: the SDK structs are json-tagged only.
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
	pack.SBOM = connector.ArtifactRef{Ref: sbomRef, Digest: zeroDigest}
	pack.Provenance = connector.ArtifactRef{Ref: provenanceRef, Digest: zeroDigest}
	pack.Signature = connector.Signature{Algorithm: "ed25519", KeyID: "test-key-1", Value: "dGVzdC1zaWduYXR1cmUtdmFsdWU="}
	pack.Digest = connector.PackContentDigest(pack)
	return pack
}

func resolverTestBinding(pack connector.ProductPack, capability string) connector.CustomerBinding {
	return connector.CustomerBinding{
		SchemaVersion: connector.CustomerBindingSchemaVersion,
		BindingKey:    resolverTestBindingKey,
		Customer:      connector.CustomerRef{Name: "acme"},
		Product: connector.ProductRef{
			ProductKey: pack.ProductKey, Version: pack.Version, Digest: pack.Digest,
		},
		Endpoints:        []connector.Endpoint{{Name: "api", URL: "https://orders.acme.internal:8443/v2"}},
		Secrets:          []connector.SecretRef{{Name: "connector-token", Ref: "secretref://vault/acme/connector"}},
		ResourceMappings: []connector.ResourceMapping{{Capability: capability, Resource: "erp_orders_internal_tbl"}},
	}
}

func resolverTestJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func resolverTestRef() evidence.ConnectorSourceRef {
	return evidence.ConnectorSourceRef{
		TenantRef:  "ent-1",
		BindingKey: resolverTestBindingKey,
		Capability: resolverTestCapability,
	}
}

func TestConnectorSourceFromDocumentsDerivesThePrivateSourceRef(t *testing.T) {
	t.Parallel()
	pack := resolverTestPack(t)
	binding := resolverTestBinding(pack, resolverTestCapability)
	got, err := connectorSourceFromDocuments(resolverTestRef(),
		resolverTestJSON(t, pack), resolverTestJSON(t, binding))
	if err != nil {
		t.Fatalf("connectorSourceFromDocuments: %v", err)
	}
	// The reference is DERIVED from the named binding, never typed by an
	// operator, and it addresses the connector binding model rather than a
	// second registry.
	if want := "connector:" + resolverTestBindingKey + "#" + resolverTestCapability; got != want {
		t.Fatalf("source ref = %q, want %q", got, want)
	}
	if got != resolverTestRef().SourceRef() {
		t.Fatalf("the resolver and ConnectorSourceRef.SourceRef disagree: %q vs %q", got, resolverTestRef().SourceRef())
	}
}

// The evidence plane OBSERVES. A data class registered onto a write capability
// would point locate at a side-effecting operation, so the refusal must come
// from THIS resolver — not incidentally from the SDK. The webhook fixture is a
// genuine, fully valid signed pack declaring both a write and a read
// capability, so the pack imports cleanly and the only thing that can refuse
// webhook.notify.send is the read-effect check itself.
func TestConnectorSourceFromDocumentsRefusesAWriteCapability(t *testing.T) {
	t.Parallel()
	pack := resolverTestPackFrom(t, "webhook-pack.yaml", "sbom.webhook.notify", "provenance.webhook.notify")
	const writeCapability = "webhook.notify.send"
	binding := resolverTestBinding(pack, writeCapability)
	ref := resolverTestRef()
	ref.Capability = writeCapability

	// The same pack's READ capability must resolve, which is what proves the
	// refusal below is about the effect and not about this fixture.
	readRef := resolverTestRef()
	readRef.Capability = "webhook.notify.read"
	if _, err := connectorSourceFromDocuments(readRef,
		resolverTestJSON(t, pack), resolverTestJSON(t, resolverTestBinding(pack, readRef.Capability))); err != nil {
		t.Fatalf("the read capability of the same pack must resolve: %v", err)
	}

	_, err := connectorSourceFromDocuments(ref,
		resolverTestJSON(t, pack), resolverTestJSON(t, binding))
	if err == nil {
		t.Fatal("connectorSourceFromDocuments registered a WRITE capability as an evidence source")
	}
	if !strings.Contains(err.Error(), "read capabilities") {
		t.Errorf("error should name the read requirement, got %v", err)
	}
}

func TestConnectorSourceFromDocumentsRefusesADigestMismatch(t *testing.T) {
	t.Parallel()
	pack := resolverTestPack(t)
	binding := resolverTestBinding(pack, resolverTestCapability)
	// The foreign key on (product_key, version, digest) constrains the table's
	// COLUMNS to each other, so a binding document pinning some other digest
	// satisfies it perfectly. The documents are the authority.
	binding.Product.Digest = "sha256:" + strings.Repeat("a", 64)

	_, err := connectorSourceFromDocuments(resolverTestRef(),
		resolverTestJSON(t, pack), resolverTestJSON(t, binding))
	if err == nil {
		t.Fatal("connectorSourceFromDocuments accepted a digest-swapped customer binding")
	}
	if !strings.Contains(err.Error(), "digest") {
		t.Errorf("error should name the digest mismatch, got %v", err)
	}
}

func TestConnectorSourceFromDocumentsRefusesAnUndeclaredCapability(t *testing.T) {
	t.Parallel()
	pack := resolverTestPack(t)
	binding := resolverTestBinding(pack, resolverTestCapability)
	ref := resolverTestRef()
	ref.Capability = "httpapi.orders.invented"

	if _, err := connectorSourceFromDocuments(ref,
		resolverTestJSON(t, pack), resolverTestJSON(t, binding)); err == nil {
		t.Fatal("connectorSourceFromDocuments accepted a capability the pinned pack does not declare")
	}
}

// A development (unsigned) pack must never become an evidence source: the whole
// point of resolving against migration 000012 is that the pack is signed.
func TestConnectorSourceFromDocumentsRefusesADevelopmentPack(t *testing.T) {
	t.Parallel()
	pack := resolverTestPack(t)
	pack.Development = true
	pack.Digest = connector.PackContentDigest(pack)
	binding := resolverTestBinding(pack, resolverTestCapability)

	if _, err := connectorSourceFromDocuments(resolverTestRef(),
		resolverTestJSON(t, pack), resolverTestJSON(t, binding)); err == nil {
		t.Fatal("connectorSourceFromDocuments accepted a development pack as an evidence source")
	}
}

// The one path that genuinely needs no database: without a pool there is no
// server-side truth to resolve against, so the resolver refuses rather than
// falling back to the operator's word.
func TestPostgresConnectorSourceResolverRefusesWithoutAPool(t *testing.T) {
	t.Parallel()
	_, err := postgresConnectorSourceResolver{}.ResolveConnectorSource(context.Background(), resolverTestRef())
	if err == nil {
		t.Fatal("the resolver derived a source reference with no database pool")
	}
}
