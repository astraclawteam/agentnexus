package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// The binding key an operator writes in a catalog is PRIVATE connector
// topology: it names the customer's own connector instance. It must never
// appear on a wire, so it is a canary here exactly like gatewayConnectorCanary.
const catalogBindingKeyCanary = "binding-CATALOG-SECRET-91-erp-prod"

const (
	catalogDataClass   = "erp.purchase_orders"
	catalogCapability  = "erp.purchase_order.read"
	undeclaredDataClass = "erp.invoices"
)

// stubConnectorSourceResolver stands in for the PostgreSQL resolver over the
// connector_products / connector_bindings tables. It derives the SAME private
// SourceRef the real one does (ConnectorSourceRef.SourceRef), so what the tests
// below exercise is the real derivation, not a test-only shape.
type stubConnectorSourceResolver struct {
	// known is the set of "<binding key>#<capability>" this tenant has bound.
	known map[string]bool
	calls int
}

func (r *stubConnectorSourceResolver) ResolveConnectorSource(_ context.Context, ref evidence.ConnectorSourceRef) (string, error) {
	r.calls++
	if !r.known[ref.BindingKey+"#"+ref.Capability] {
		return "", errors.New("no connector binding of this tenant declares the named capability under that binding key")
	}
	return ref.SourceRef(), nil
}

func catalogResolverWith(pairs ...string) *stubConnectorSourceResolver {
	known := make(map[string]bool, len(pairs))
	for _, pair := range pairs {
		known[pair] = true
	}
	return &stubConnectorSourceResolver{known: known}
}

// oneSourceCatalog is a minimal valid catalog declaring exactly one data class.
func oneSourceCatalog() evidence.SourceCatalog {
	return evidence.SourceCatalog{
		SchemaVersion: evidence.SourceCatalogSchemaVersion,
		Sources: []evidence.CatalogSource{{
			TenantRef:         "ent-1",
			DataClass:         catalogDataClass,
			Connector:         evidence.CatalogConnectorRef{BindingKey: catalogBindingKeyCanary, Capability: catalogCapability},
			AccessCapability:  "knowledge.suggest",
			ResourceType:      "knowledge",
			ResourceID:        "kb-space",
			CachedReadAllowed: true,
		}},
	}
}

// newCatalogRegisteredService builds the evidence service with an EMPTY registry
// and then populates it ONLY through ApplySourceCatalog. Nothing here calls
// RegisterSourceBinding directly: the point is to exercise the registration path
// a deployment actually uses.
func newCatalogRegisteredService(t *testing.T, catalog evidence.SourceCatalog) *evidence.Service {
	t.Helper()
	contentSource := evidence.NewMemoryContentSource()
	svc := evidence.NewService(
		evidence.NewMemoryStore(),
		evidence.NewMemoryObjectStore(),
		evidence.StaticKeyProvider{Material: evidence.KeyMaterial{Ref: "test-key-catalog", Key: bytes.Repeat([]byte{0x31}, 32)}},
		contentSource,
		policy.NewCapabilityEvaluator(authorizationPolicySource()),
		&gatewayEvidenceAudit{},
	)
	resolver := catalogResolverWith(catalogBindingKeyCanary + "#" + catalogCapability)
	registered, err := evidence.ApplySourceCatalog(context.Background(), svc, resolver, catalog)
	if err != nil {
		t.Fatalf("ApplySourceCatalog: %v", err)
	}
	// Seed the content source at the reference the catalog DERIVED, so a change
	// to the derivation breaks this test rather than silently decoupling the
	// registry from the source plane.
	for _, binding := range registered {
		contentSource.Seed(binding.SourceRef, []evidence.Record{
			{"po_number": "PO-1", "body": gatewayContentCanary},
		})
	}
	return svc
}

// The defect this whole change exists to close, stated behaviourally and in
// BOTH directions.
//
// Before: RegisterSourceBinding had no non-test caller, the registry was empty,
// and /v1/runtime/locate answered 403 evidence_denied (not_resolvable) for every
// data class — on a surface that reported healthy to every probe.
//
// The two halves are inseparable. The declared half alone would pass against a
// lookup that resolved anything; the undeclared half alone would pass against
// the empty registry this replaces. Only together do they say that registration
// is what decided it. not_resolvable for an unregistered data class is CORRECT
// and must stay correct: the fix is a populated registry, never a lenient
// lookup.
func TestSourceCatalogRegistrationDecidesLocateInBothDirections(t *testing.T) {
	t.Parallel()
	svc := newCatalogRegisteredService(t, oneSourceCatalog())
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	declared := postEvidence(t, router, "/v1/runtime/locate",
		evidenceLocateBody(catalogDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if declared.Code == http.StatusForbidden {
		t.Fatalf("a catalog-registered data class still denied: status=403 body=%s", declared.Body.String())
	}
	if declared.Code != http.StatusOK {
		t.Fatalf("locate for a registered data class: status=%d want=200 body=%s", declared.Code, declared.Body.String())
	}

	undeclared := postEvidence(t, router, "/v1/runtime/locate",
		evidenceLocateBody(undeclaredDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if undeclared.Code != http.StatusForbidden {
		t.Fatalf("an UNregistered data class must still deny: status=%d want=403 body=%s",
			undeclared.Code, undeclared.Body.String())
	}
	if reason, _ := decodeEvidenceJSON(t, undeclared)["error"].(string); reason != "evidence_denied" {
		t.Fatalf("unregistered deny envelope = %q, want evidence_denied", reason)
	}
}

// Registration must not put connector topology on a wire. The binding key an
// operator names in the catalog, and the private SourceRef derived from it, are
// server-side truth: a locate response carries the data class and an opaque
// evd_ handle, and nothing else.
func TestSourceCatalogRegistrationKeepsConnectorTopologyOffTheWire(t *testing.T) {
	t.Parallel()
	svc := newCatalogRegisteredService(t, oneSourceCatalog())
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	located := postEvidence(t, router, "/v1/runtime/locate",
		evidenceLocateBody(catalogDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if located.Code != http.StatusOK {
		t.Fatalf("locate status=%d body=%s", located.Code, located.Body.String())
	}
	body := located.Body.String()
	for _, leak := range []string{catalogBindingKeyCanary, "connector:", catalogCapability} {
		if strings.Contains(body, leak) {
			t.Fatalf("locate response leaked private source topology %q: %s", leak, body)
		}
	}
}

// A catalog naming a connector binding the tenant does not have must register
// NOTHING — not the entries before it, not the entries after it. A half-applied
// catalog is a registry an operator cannot reason about.
func TestApplySourceCatalogRegistersNothingWhenOneEntryDoesNotResolve(t *testing.T) {
	t.Parallel()
	catalog := oneSourceCatalog()
	catalog.Sources = append(catalog.Sources, evidence.CatalogSource{
		TenantRef:        "ent-1",
		DataClass:        undeclaredDataClass,
		Connector:        evidence.CatalogConnectorRef{BindingKey: "binding-that-does-not-exist", Capability: catalogCapability},
		AccessCapability: "knowledge.suggest",
		ResourceType:     "knowledge",
		ResourceID:       "kb-space",
	})

	store := evidence.NewMemoryStore()
	svc := evidence.NewService(
		store,
		evidence.NewMemoryObjectStore(),
		evidence.StaticKeyProvider{Material: evidence.KeyMaterial{Ref: "test-key-catalog", Key: bytes.Repeat([]byte{0x31}, 32)}},
		evidence.NewMemoryContentSource(),
		policy.NewCapabilityEvaluator(authorizationPolicySource()),
		&gatewayEvidenceAudit{},
	)
	resolver := catalogResolverWith(catalogBindingKeyCanary + "#" + catalogCapability)
	if _, err := evidence.ApplySourceCatalog(context.Background(), svc, resolver, catalog); err == nil {
		t.Fatal("ApplySourceCatalog accepted an entry naming a connector binding that does not exist")
	}
	// The FIRST entry resolves cleanly, so if resolution and registration were
	// interleaved it would already be in the store.
	if _, err := store.GetSourceBinding(context.Background(), "ent-1", catalogDataClass); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("a rejected catalog left a partially applied registry: GetSourceBinding err=%v, want ErrNotFound", err)
	}
	if resolver.calls != 2 {
		t.Fatalf("every connector reference must be resolved before the first write: calls=%d want=2", resolver.calls)
	}
}

// Applying the same catalog again is what every restart does. It must not
// rebind a live handle (a changed binding id denies at binding_rebound) and must
// not lower the source version (a changed version denies at
// source_version_stale). Both would take a working deployment down on redeploy.
func TestApplySourceCatalogIsIdempotentAcrossRestarts(t *testing.T) {
	t.Parallel()
	svc := newCatalogRegisteredService(t, oneSourceCatalog())
	router := newEvidenceTestRouter(t, validSessionStub(), svc, &recordingTrustAudit{})

	located := postEvidence(t, router, "/v1/runtime/locate",
		evidenceLocateBody(catalogDataClass, gatewayPurpose, 0), addAuthorizationSession)
	if located.Code != http.StatusOK {
		t.Fatalf("locate status=%d body=%s", located.Code, located.Body.String())
	}
	payload := decodeEvidenceJSON(t, located)
	businessContextRef, _ := payload["business_context_ref"].(string)
	handles, _ := payload["evidence"].([]any)
	if len(handles) != 1 {
		t.Fatalf("locate payload = %s", located.Body.String())
	}
	handle, _ := handles[0].(map[string]any)
	evidenceRef, _ := handle["evidence_ref"].(string)

	// The restart: the same catalog, applied again through the same service.
	resolver := catalogResolverWith(catalogBindingKeyCanary + "#" + catalogCapability)
	if _, err := evidence.ApplySourceCatalog(context.Background(), svc, resolver, oneSourceCatalog()); err != nil {
		t.Fatalf("re-applying the same catalog: %v", err)
	}

	read := postEvidence(t, router, "/v1/runtime/read",
		evidenceReadBody(businessContextRef, evidenceRef, gatewayPurpose, 0), addAuthorizationSession)
	if read.Code != http.StatusOK {
		t.Fatalf("read after a catalog re-apply: status=%d body=%s", read.Code, read.Body.String())
	}
	if decision, _ := decodeEvidenceJSON(t, read)["decision"].(string); decision != "allow" {
		t.Fatalf("a handle located before a catalog re-apply must still read: decision=%q body=%s",
			decision, read.Body.String())
	}
}

// A catalog registers connector-BACKED sources, so a context without connector
// capability must still be refused. The catalog derives SourceCapability from
// the declared connector capability rather than accepting one, so there is no
// way to write an entry that opts out of the AstraClaw boundary check.
func TestSourceCatalogEntriesStayConnectorBacked(t *testing.T) {
	t.Parallel()
	store := evidence.NewMemoryStore()
	svc := evidence.NewService(
		store,
		evidence.NewMemoryObjectStore(),
		evidence.StaticKeyProvider{Material: evidence.KeyMaterial{Ref: "test-key-catalog", Key: bytes.Repeat([]byte{0x31}, 32)}},
		evidence.NewMemoryContentSource(),
		policy.NewCapabilityEvaluator(authorizationPolicySource()),
		&gatewayEvidenceAudit{},
	)
	resolver := catalogResolverWith(catalogBindingKeyCanary + "#" + catalogCapability)
	registered, err := evidence.ApplySourceCatalog(context.Background(), svc, resolver, oneSourceCatalog())
	if err != nil {
		t.Fatalf("ApplySourceCatalog: %v", err)
	}
	if len(registered) != 1 {
		t.Fatalf("registered %d bindings, want 1", len(registered))
	}
	want := policy.ConnectorCapabilityPrefix + catalogCapability
	if registered[0].SourceCapability != want {
		t.Fatalf("SourceCapability = %q, want %q so connectorBacked() holds", registered[0].SourceCapability, want)
	}
	if !policy.IsConnectorCapability(policy.Capability(registered[0].SourceCapability)) {
		t.Fatal("a catalog-registered source must be connector-backed")
	}
}
