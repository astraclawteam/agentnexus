package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type stubResolver struct {
	fail  bool
	calls int
}

func (r *stubResolver) ResolveConnectorSource(_ context.Context, ref ConnectorSourceRef) (string, error) {
	r.calls++
	if r.fail {
		return "", errors.New("no connector binding of this tenant declares the named capability under that binding key")
	}
	return ref.SourceRef(), nil
}

func catalogTestService(t *testing.T) *Service {
	return newFixture(t).svc
}

func validCatalogSource() CatalogSource {
	return CatalogSource{
		TenantRef:         testTenant,
		DataClass:         "erp.purchase_orders",
		Connector:         CatalogConnectorRef{BindingKey: "erp-prod", Capability: "erp.purchase_order.read"},
		AccessCapability:  "knowledge.suggest",
		ResourceType:      "knowledge",
		ResourceID:        "kb-space",
		CachedReadAllowed: true,
	}
}

func validCatalog() SourceCatalog {
	return SourceCatalog{SchemaVersion: SourceCatalogSchemaVersion, Sources: []CatalogSource{validCatalogSource()}}
}

// A catalog is deployment configuration, so a typo must fail loudly rather than
// default. Every case here would otherwise register a binding the operator did
// not describe, or none at all while looking configured.
func TestParseSourceCatalogRefusesUnusableDocuments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, doc string }{
		{"not json", `nope`},
		{"wrong schema version", `{"schema_version":"evidence.source_catalog/v2","sources":[]}`},
		{"missing schema version", `{"sources":[]}`},
		{"no sources", `{"schema_version":"evidence.source_catalog/v1","sources":[]}`},
		{"unknown top-level field", `{"schema_version":"evidence.source_catalog/v1","sources":[],"registry":"x"}`},
		{"unknown source field", `{"schema_version":"evidence.source_catalog/v1","sources":[
			{"tenant_ref":"ent-1","data_class":"c","source_ref":"connector:typed-by-hand",
			 "connector":{"binding_key":"b","capability":"x.read"},
			 "access_capability":"knowledge.suggest","resource_type":"knowledge","resource_id":"kb"}]}`},
		{"trailing content", `{"schema_version":"evidence.source_catalog/v1","sources":[]} {"and":"more"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseSourceCatalog([]byte(tc.doc)); err == nil {
				t.Fatal("ParseSourceCatalog accepted an unusable document")
			} else if !errors.Is(err, ErrInvalidCatalog) {
				t.Errorf("error must be an ErrInvalidCatalog, got %v", err)
			}
		})
	}
}

func TestValidateSourceCatalogRefusesUnusableEntries(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*CatalogSource)
		want   string
	}{
		{"no tenant", func(s *CatalogSource) { s.TenantRef = "" }, "tenant_ref"},
		{"untrimmed data class", func(s *CatalogSource) { s.DataClass = " padded " }, "data_class"},
		{"control byte in resource id", func(s *CatalogSource) { s.ResourceID = "kb\x00space" }, "resource_id"},
		{"no connector reference", func(s *CatalogSource) { s.Connector = CatalogConnectorRef{} }, "binding_key"},
		{"binding key carrying the ref separator", func(s *CatalogSource) { s.Connector.BindingKey = "erp#prod" }, "binding_key"},
		// The authorization target must be a pair the neutral policy grants.
		// Otherwise the class registers and then denies every locate at
		// policy_denied forever — the same silent shape a catalog exists to end.
		{"capability the policy does not grant", func(s *CatalogSource) { s.AccessCapability = "knowledge.invented" }, "neutral policy"},
		{"capability on the wrong resource type", func(s *CatalogSource) { s.ResourceType = "workflow" }, "neutral policy"},
		{"a connector capability as the access capability", func(s *CatalogSource) { s.AccessCapability = "connector.docs.read" }, "neutral policy"},
		{"negative retention", func(s *CatalogSource) { s.RetentionTTLSeconds = -1 }, "retention_ttl_seconds"},
		{"authority tier with no bound", func(s *CatalogSource) {
			s.ObservationAuthority = &CatalogObservationAuthority{Tier: AuthorityTierSystemOfRecord}
		}, "freshness_bound_seconds"},
		{"freshness bound with no tier", func(s *CatalogSource) {
			s.ObservationAuthority = &CatalogObservationAuthority{FreshnessBoundSeconds: 60}
		}, "tier"},
		{"a tier outside the frozen set", func(s *CatalogSource) {
			s.ObservationAuthority = &CatalogObservationAuthority{Tier: "best_effort", FreshnessBoundSeconds: 60}
		}, "frozen tiers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			source := validCatalogSource()
			tc.mutate(&source)
			err := ValidateSourceCatalog(SourceCatalog{SchemaVersion: SourceCatalogSchemaVersion, Sources: []CatalogSource{source}})
			if err == nil {
				t.Fatal("ValidateSourceCatalog accepted an unusable entry")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got %v", tc.want, err)
			}
		})
	}
}

// Two entries for one (tenant, data class) would upsert one over the other, so
// whichever came last would silently win.
func TestValidateSourceCatalogRefusesADuplicateDataClass(t *testing.T) {
	t.Parallel()
	catalog := validCatalog()
	second := validCatalogSource()
	second.Connector.BindingKey = "erp-standby"
	catalog.Sources = append(catalog.Sources, second)
	if err := ValidateSourceCatalog(catalog); err == nil {
		t.Fatal("ValidateSourceCatalog accepted the same data class twice for one tenant")
	}
}

// The half of the behaviour this whole change exists for, at the service level:
// a declared class resolves, an undeclared one is still ErrNotFound. Both, or
// the test would pass against a lenient lookup.
func TestApplySourceCatalogRegistersOnlyWhatItDeclares(t *testing.T) {
	t.Parallel()
	svc := catalogTestService(t)
	registered, err := ApplySourceCatalog(context.Background(), svc, &stubResolver{}, validCatalog())
	if err != nil {
		t.Fatalf("ApplySourceCatalog: %v", err)
	}
	if len(registered) != 1 {
		t.Fatalf("registered %d bindings, want 1", len(registered))
	}

	stored, err := svc.store.GetSourceBinding(context.Background(), testTenant, "erp.purchase_orders")
	if err != nil {
		t.Fatalf("a declared data class must resolve: %v", err)
	}
	if stored.SourceRef != "connector:erp-prod#erp.purchase_order.read" {
		t.Fatalf("SourceRef = %q, want the reference derived from the named connector binding", stored.SourceRef)
	}
	// Derived, never declared: a catalog cannot register a connector source that
	// opts out of the credential-derived connector capability check.
	if !stored.connectorBacked() {
		t.Fatalf("SourceCapability = %q, want a connector-backed binding", stored.SourceCapability)
	}

	if _, err := svc.store.GetSourceBinding(context.Background(), testTenant, "erp.invoices"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an UNdeclared data class must stay not-found: err=%v", err)
	}
	// Tenancy is part of the key: another tenant's registry is untouched.
	if _, err := svc.store.GetSourceBinding(context.Background(), "ten_other", "erp.purchase_orders"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a declaration for one tenant must not resolve for another: err=%v", err)
	}
}

func TestApplySourceCatalogCarriesTheObservationAuthority(t *testing.T) {
	t.Parallel()
	catalog := validCatalog()
	catalog.Sources[0].ObservationAuthority = &CatalogObservationAuthority{
		Tier: AuthorityTierAuthoritativeReplica, FreshnessBoundSeconds: 900,
	}
	catalog.Sources[0].RetentionTTLSeconds = 3600

	svc := catalogTestService(t)
	registered, err := ApplySourceCatalog(context.Background(), svc, &stubResolver{}, catalog)
	if err != nil {
		t.Fatalf("ApplySourceCatalog: %v", err)
	}
	if got := registered[0].AuthorityTier; got != AuthorityTierAuthoritativeReplica {
		t.Errorf("AuthorityTier = %q", got)
	}
	if got := registered[0].FreshnessBound; got != 15*time.Minute {
		t.Errorf("FreshnessBound = %v, want 15m", got)
	}
	if got := registered[0].RetentionTTL; got != time.Hour {
		t.Errorf("RetentionTTL = %v, want 1h", got)
	}
}

// Without a resolver there is nothing to derive a source reference from. Falling
// back to an operator-supplied one is exactly the parallel registry this design
// refuses to become, so an unresolved catalog fails closed.
func TestApplySourceCatalogRefusesWithoutAResolver(t *testing.T) {
	t.Parallel()
	if _, err := ApplySourceCatalog(context.Background(), catalogTestService(t), nil, validCatalog()); err == nil {
		t.Fatal("ApplySourceCatalog applied a catalog with no connector source resolver")
	}
}

func TestApplySourceCatalogResolvesEveryEntryBeforeWritingAny(t *testing.T) {
	t.Parallel()
	svc := catalogTestService(t)
	resolver := &stubResolver{fail: true}
	if _, err := ApplySourceCatalog(context.Background(), svc, resolver, validCatalog()); err == nil {
		t.Fatal("ApplySourceCatalog registered an entry whose connector source does not resolve")
	}
	if _, err := svc.store.GetSourceBinding(context.Background(), testTenant, "erp.purchase_orders"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a failed resolution must leave the registry untouched: err=%v", err)
	}
}
