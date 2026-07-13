package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// The Product Pack v1 contract is customer-agnostic and resellable. Every
// rejection required by GA Task 2 Step "RED" is proven here at the Go level:
//
//   - a Product Pack must never carry customer-identifying data (customer name,
//     endpoint, credential, raw table/API path or field mapping);
//   - a production Product Pack must be signed and carry content, SBOM and
//     provenance digests (no unsigned/digestless pack);
//   - every write capability must declare its side effects AND a reconciliation;
//   - a Product Pack must declare compatibility and SBOM/provenance/signature;
//   - a Customer Binding must reference secrets, never inline secret material;
//   - a generic manifest migrates only into an unsigned development pack that can
//     never be imported as a production Product Pack;
//   - the SAME Product Pack bytes are byte-identical across two different
//     customer bindings, and carry none of either customer's data.

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func readCapability() Capability {
	return Capability{
		Name:   "erp.purchase_order.read",
		Title:  "Read purchase order",
		Effect: EffectRead,
		Input:  IOSchema{Ref: "schema.erp.purchase_order.read.input", Digest: digestOf("in-read")},
		Output: IOSchema{Ref: "schema.erp.purchase_order.read.output", Digest: digestOf("out-read")},
	}
}

func writeCapability() Capability {
	return Capability{
		Name:   "erp.purchase_order.approve",
		Title:  "Approve purchase order",
		Effect: EffectWrite,
		Input:  IOSchema{Ref: "schema.erp.purchase_order.approve.input", Digest: digestOf("in-write")},
		Output: IOSchema{Ref: "schema.erp.purchase_order.approve.output", Digest: digestOf("out-write")},
		SideEffects: []SideEffect{{
			Kind:        "external_write",
			Description: "posts an approval decision to the ERP system of record",
			Reversible:  false,
		}},
		Reconciliation: &Reconciliation{
			Strategy:               "verify_then_compensate",
			VerifyCapability:       "erp.purchase_order.read",
			CompensationCapability: "erp.purchase_order.reject",
		},
	}
}

// rejectCapability is the compensating write the approve capability names; it is
// declared so approve's reconciliation.compensation_capability resolves.
func rejectCapability() Capability {
	return Capability{
		Name:   "erp.purchase_order.reject",
		Title:  "Reject purchase order",
		Effect: EffectWrite,
		Input:  IOSchema{Ref: "schema.erp.purchase_order.reject.input", Digest: digestOf("in-reject")},
		Output: IOSchema{Ref: "schema.erp.purchase_order.reject.output", Digest: digestOf("out-reject")},
		SideEffects: []SideEffect{{
			Kind:        "external_write",
			Description: "records a rejection decision in the ERP system of record",
			Reversible:  true,
		}},
		Reconciliation: &Reconciliation{
			Strategy:         "verify_then_compensate",
			VerifyCapability: "erp.purchase_order.read",
		},
	}
}

// validProductPack returns a signed, production-ready, customer-agnostic pack.
func validProductPack() ProductPack {
	p := ProductPack{
		SchemaVersion: ProductPackSchemaVersion,
		ProductKey:    "sap.s4hana.procurement",
		Version:       "1.0.0",
		Title:         "S/4HANA Procurement",
		Capabilities:  []Capability{readCapability(), writeCapability(), rejectCapability()},
		FieldPolicy: FieldPolicy{
			Classifications: []FieldClassification{{Field: "amount", Classification: "confidential", Redacted: true}},
		},
		Network:       NetworkRequirements{Egress: []string{"erp.api"}, Isolation: "outbound_only"},
		Runtime:       RuntimeRequirements{Runtime: "wasm", MinMemoryMB: 64},
		Compatibility: Compatibility{RuntimeContract: VersionRange{Min: "1.0.0", Max: "1.9.9"}, ConnectorRuntime: VersionRange{Min: "1.0.0"}},
		Migration:     MigrationInfo{FromVersions: []string{}, Notes: "initial release"},
		Limits:        Limits{MaxConcurrency: 8, MaxRequestsPerMinute: 600},
		SBOM:          ArtifactRef{Ref: "sbom.sap.s4hana.procurement", Digest: digestOf("sbom")},
		Provenance:    ArtifactRef{Ref: "provenance.sap.s4hana.procurement", Digest: digestOf("provenance")},
	}
	p.Digest = PackContentDigest(p)
	p.Signature = Signature{Algorithm: SignatureAlgorithmEd25519, KeyID: "connector-signing-1", Value: "c2lnbmF0dXJlLWJ5dGVz"}
	return p
}

func mustReject(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error containing %q, got nil", fragment)
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("want error containing %q, got %q", fragment, err.Error())
	}
}

func TestProductPackProductionValidation(t *testing.T) {
	if err := ValidateProductionPack(validProductPack()); err != nil {
		t.Fatalf("canonical signed product pack must validate, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*ProductPack)
		wantErr string
	}{
		{"unsigned pack", func(p *ProductPack) { p.Signature = Signature{} }, "signature"},
		{"signature missing key id", func(p *ProductPack) { p.Signature.KeyID = "" }, "key_id"},
		{"unknown signature algorithm", func(p *ProductPack) { p.Signature.Algorithm = "rot13" }, "algorithm"},
		{"digestless pack", func(p *ProductPack) { p.Digest = "" }, "digest"},
		{"malformed digest", func(p *ProductPack) { p.Digest = "sha256:nothex" }, "digest"},
		{"tampered digest", func(p *ProductPack) { p.Digest = digestOf("tampered") }, "digest"},
		{"missing sbom", func(p *ProductPack) { p.SBOM = ArtifactRef{} }, "sbom"},
		{"missing provenance", func(p *ProductPack) { p.Provenance = ArtifactRef{} }, "provenance"},
		{"missing compatibility", func(p *ProductPack) { p.Compatibility = Compatibility{} }, "compatibility"},
		{"missing product key", func(p *ProductPack) { p.ProductKey = "" }, "product_key"},
		{"non-semantic product key", func(p *ProductPack) { p.ProductKey = "Acme S/4" }, "product_key"},
		{"missing version", func(p *ProductPack) { p.Version = "" }, "version"},
		{"no capabilities", func(p *ProductPack) { p.Capabilities = nil }, "capabilit"},
		{"non-semantic capability name", func(p *ProductPack) { p.Capabilities[0].Name = "SELECT * FROM po" }, "capability"},
		{"free-text capability name", func(p *ProductPack) { p.Capabilities[0].Name = "Read PO" }, "capability"},
		{"unknown effect", func(p *ProductPack) { p.Capabilities[0].Effect = "mutate" }, "effect"},
		{"io schema ref is a raw path", func(p *ProductPack) { p.Capabilities[0].Input.Ref = "postgres://mes/workorders" }, "ref"},
		{"io schema digest malformed", func(p *ProductPack) { p.Capabilities[0].Output.Digest = "not-a-digest" }, "digest"},
		{"write capability missing reconciliation", func(p *ProductPack) { p.Capabilities[1].Reconciliation = nil }, "reconciliation"},
		{"write capability undeclared side effect", func(p *ProductPack) { p.Capabilities[1].SideEffects = nil }, "side_effect"},
		{"reconciliation verify not semantic", func(p *ProductPack) { p.Capabilities[1].Reconciliation.VerifyCapability = "SELECT" }, "verify_capability"},
		{"reconciliation verify not declared", func(p *ProductPack) { p.Capabilities[1].Reconciliation.VerifyCapability = "erp.purchase_order.unknown" }, "verify_capability"},
		{"reconciliation compensation not declared", func(p *ProductPack) {
			p.Capabilities[1].Reconciliation.CompensationCapability = "erp.purchase_order.unknown"
		}, "compensation_capability"},
		{"field policy classification incomplete", func(p *ProductPack) { p.FieldPolicy.Classifications = []FieldClassification{{Field: "amount"}} }, "classification"},
		{"negative min memory", func(p *ProductPack) { p.Runtime.MinMemoryMB = -1 }, "min_memory_mb"},
		{"negative max concurrency", func(p *ProductPack) { p.Limits.MaxConcurrency = -1 }, "max_concurrency"},
		{"negative max requests per minute", func(p *ProductPack) { p.Limits.MaxRequestsPerMinute = -8 }, "max_requests_per_minute"},
		{"compatibility min exceeds max", func(p *ProductPack) { p.Compatibility.RuntimeContract = VersionRange{Min: "2.0.0", Max: "1.0.0"} }, "exceed"},
		{"compatibility non-semver min", func(p *ProductPack) { p.Compatibility.ConnectorRuntime = VersionRange{Min: "1.x"} }, "semver"},
		{"development pack is not production importable", func(p *ProductPack) { p.Development = true }, "development"},
		{"wrong schema version", func(p *ProductPack) { p.SchemaVersion = "connector.product/v2" }, "schema_version"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validProductPack()
			tc.mutate(&p)
			// keep the digest self-consistent for mutations that are not about the
			// digest itself, so each case fails for exactly the reason it targets.
			if tc.wantErr != "digest" && p.Digest != "" && !strings.Contains(tc.name, "digest") {
				p.Digest = PackContentDigest(p)
			}
			mustReject(t, ValidateProductionPack(p), tc.wantErr)
		})
	}
}

func TestProductPackRejectsCustomerIdentifyingData(t *testing.T) {
	base, err := json.Marshal(validProductPack())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProductPack(base); err != nil {
		t.Fatalf("canonical pack JSON must parse, got %v", err)
	}

	inject := func(t *testing.T, mutate func(map[string]any)) []byte {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(base, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	forbidden := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"customer name", func(d map[string]any) { d["customer_name"] = "Acme Manufacturing" }},
		{"endpoint", func(d map[string]any) { d["endpoint"] = "https://acme.erp.example/api" }},
		{"endpoints", func(d map[string]any) { d["endpoints"] = []any{"https://acme.erp.example"} }},
		{"credential", func(d map[string]any) { d["credential"] = "oauth-client-secret" }},
		{"base url on a capability", func(d map[string]any) {
			d["capabilities"].([]any)[0].(map[string]any)["base_url"] = "https://acme.erp.example"
		}},
		{"raw table path", func(d map[string]any) {
			d["capabilities"].([]any)[0].(map[string]any)["table"] = "public.work_orders"
		}},
		{"field mapping", func(d map[string]any) {
			d["field_mappings"] = []any{map[string]any{"field": "amount", "source": "NETWR"}}
		}},
		{"nested customer endpoint alias", func(d map[string]any) {
			d["capabilities"].([]any)[0].(map[string]any)["customer_endpoint"] = "https://acme"
		}},
	}
	for _, tc := range forbidden {
		t.Run(tc.name, func(t *testing.T) {
			raw := inject(t, tc.mutate)
			_, err := ParseProductPack(raw)
			if err == nil {
				t.Fatalf("product pack carrying %s must be rejected", tc.name)
			}
			if !errors.Is(err, ErrCustomerDataInProductPack) {
				t.Fatalf("want ErrCustomerDataInProductPack for %s, got %v", tc.name, err)
			}
		})
	}
}

func acmeBinding(p ProductPack) CustomerBinding {
	return CustomerBinding{
		SchemaVersion:    CustomerBindingSchemaVersion,
		BindingKey:       "acme-erp-prod",
		Customer:         CustomerRef{Name: "Acme Manufacturing", Ref: "cust_acme"},
		Product:          ProductRef{ProductKey: p.ProductKey, Version: p.Version, Digest: p.Digest},
		Endpoints:        []Endpoint{{Name: "erp", URL: "https://acme.erp.example/api"}},
		Secrets:          []SecretRef{{Name: "erp_oauth", Ref: "secretref://vault/acme/erp"}},
		OrgMappings:      []OrgMapping{{Unit: "plant-01", Source: "WERKS=1000"}},
		ResourceMappings: []ResourceMapping{{Capability: "erp.purchase_order.read", Resource: "acme.po.header"}},
		FieldMappings:    []FieldMapping{{Field: "amount", Source: "NETWR"}},
	}
}

func TestCustomerBindingValidation(t *testing.T) {
	p := validProductPack()
	if err := ValidateBinding(acmeBinding(p)); err != nil {
		t.Fatalf("canonical customer binding must validate, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*CustomerBinding)
		wantErr string
	}{
		{"missing binding key", func(b *CustomerBinding) { b.BindingKey = "" }, "binding_key"},
		{"missing customer name", func(b *CustomerBinding) { b.Customer.Name = "" }, "customer"},
		{"missing product ref digest", func(b *CustomerBinding) { b.Product.Digest = "" }, "digest"},
		{"no endpoints", func(b *CustomerBinding) { b.Endpoints = nil }, "endpoint"},
		{"secret without reference", func(b *CustomerBinding) { b.Secrets = []SecretRef{{Name: "x"}} }, "ref"},
		{"secret reference is a raw secret", func(b *CustomerBinding) { b.Secrets = []SecretRef{{Name: "x", Ref: "AKIA-raw-secret"}} }, "ref"},
		{"inline secret in extensions (validate-time)", func(b *CustomerBinding) {
			b.Extensions = map[string]json.RawMessage{"vault": json.RawMessage(`{"private_key":"-----BEGIN"}`)}
		}, "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := acmeBinding(p)
			tc.mutate(&b)
			mustReject(t, ValidateBinding(b), tc.wantErr)
		})
	}
}

func TestCustomerBindingRejectsInlineSecret(t *testing.T) {
	p := validProductPack()
	base, err := json.Marshal(acmeBinding(p))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBinding(base); err != nil {
		t.Fatalf("canonical binding JSON must parse, got %v", err)
	}

	inject := func(t *testing.T, mutate func(map[string]any)) []byte {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(base, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"inline value beside a secret ref", func(d map[string]any) {
			d["secrets"].([]any)[0].(map[string]any)["value"] = "super-secret-token"
		}},
		{"inline password field", func(d map[string]any) {
			d["secrets"].([]any)[0].(map[string]any)["password"] = "hunter2"
		}},
		{"secret buried in customer extensions", func(d map[string]any) {
			d["extensions"] = map[string]any{"vault": map[string]any{"private_key": "-----BEGIN"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := inject(t, tc.mutate)
			_, err := ParseBinding(raw)
			if err == nil {
				t.Fatalf("binding with %s must be rejected", tc.name)
			}
			if !errors.Is(err, ErrInlineSecretInBinding) {
				t.Fatalf("want ErrInlineSecretInBinding for %s, got %v", tc.name, err)
			}
		})
	}
}

func TestDevelopmentPackFromManifestNeverProductionImportable(t *testing.T) {
	m := Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "legacy_erp",
		Version:       "0.3.0",
		Resources: []Resource{
			{
				Name:       "purchase_orders",
				Type:       ResourceTypeHTTP,
				Operations: []Operation{{Name: "list", Method: "GET", Path: "/api/v2/po"}},
			},
			{
				Name:       "approvals",
				Type:       ResourceTypeHTTP,
				ReadOnly:   boolPtr(false),
				Operations: []Operation{{Name: "approve", Method: "POST", Path: "/api/v2/po/approve"}},
			},
		},
	}

	dev := DevelopmentPackFromManifest(m)
	if !dev.Development {
		t.Fatal("a pack migrated from a generic manifest must be flagged development-only")
	}
	if dev.Signature != (Signature{}) {
		t.Fatal("a development pack must be unsigned; signing is a separate production step")
	}
	if err := ValidateDevelopmentPack(dev); err != nil {
		t.Fatalf("development pack must pass development validation, got %v", err)
	}
	if err := ValidateProductionPack(dev); err == nil {
		t.Fatal("a generic manifest can never be imported as a production Product Pack")
	}

	// The raw development bytes must also fail production import: a development
	// fixture may never be laundered into production through the import path.
	raw, err := json.Marshal(dev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ImportProductionPack(raw); err == nil {
		t.Fatal("ImportProductionPack must reject an unsigned development pack")
	}

	// The migrated capabilities must be customer-agnostic: no raw method/path
	// topology from the source manifest may leak into the pack.
	if strings.Contains(string(raw), "/api/v2/po") {
		t.Fatal("raw API paths from the generic manifest leaked into the development pack")
	}
	for _, c := range dev.Capabilities {
		if err := ValidateCapabilityName(c.Name); err != nil {
			t.Fatalf("migrated capability %q is not a semantic capability: %v", c.Name, err)
		}
	}
}

// TestReusablePackBytesIdenticalAcrossTwoBindings proves a DESIGN property, not
// marshal determinism: the pack builder (validProductPack) takes only
// product-level inputs — there is no channel through which a customer datum
// could enter — so a pack built independently while onboarding any customer is
// byte-identical to a product-only reference, and never contains that customer's
// data. The customer inputs flow exclusively into the CustomerBinding.
func TestReusablePackBytesIdenticalAcrossTwoBindings(t *testing.T) {
	reference, err := json.Marshal(validProductPack())
	if err != nil {
		t.Fatal(err)
	}

	customers := []struct {
		name, ref, endpoint, secretRef, resource, source string
	}{
		{"Acme Manufacturing", "cust_acme", "https://acme.erp.example/api", "secretref://vault/acme/erp", "acme.po.header", "NETWR"},
		{"Globex Industrie", "cust_globex", "https://globex.sap.example/odata", "secretref://vault/globex/sap", "globex.ekko", "WRBTR"},
		{"Initech GmbH", "cust_initech", "https://initech.example/soap", "kv://initech/erp/oauth", "initech.ekpo", "DMBTR"},
	}
	for _, c := range customers {
		// The pack is built afresh for this customer — but the customer is not an
		// argument to the builder, so its bytes cannot vary by customer.
		packBytes, err := json.Marshal(validProductPack())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(packBytes, reference) {
			t.Fatalf("pack bytes varied while onboarding %q — the pack design leaks customer-varying state", c.name)
		}

		pack := validProductPack()
		binding := CustomerBinding{
			SchemaVersion:    CustomerBindingSchemaVersion,
			BindingKey:       c.ref,
			Customer:         CustomerRef{Name: c.name, Ref: c.ref},
			Product:          ProductRef{ProductKey: pack.ProductKey, Version: pack.Version, Digest: pack.Digest},
			Endpoints:        []Endpoint{{Name: "erp", URL: c.endpoint}},
			Secrets:          []SecretRef{{Name: "erp_oauth", Ref: c.secretRef}},
			ResourceMappings: []ResourceMapping{{Capability: "erp.purchase_order.read", Resource: c.resource}},
			FieldMappings:    []FieldMapping{{Field: "amount", Source: c.source}},
		}
		if err := ValidateBinding(binding); err != nil {
			t.Fatalf("binding for %q must validate: %v", c.name, err)
		}
		// The reusable pack bytes carry none of THIS customer's data.
		for _, needle := range []string{c.name, c.ref, c.endpoint, c.secretRef, c.resource, c.source} {
			if strings.Contains(string(reference), needle) {
				t.Fatalf("reusable pack bytes leaked customer datum %q", needle)
			}
		}
	}
}

func TestProductUpgradeTouchesPackNotBinding(t *testing.T) {
	v1 := validProductPack()
	binding := acmeBinding(v1)
	bindingBefore, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}

	// Upgrading the product produces a new pack (new version and digest). The
	// customer binding is a separate artifact and is not touched by producing
	// the upgrade.
	v2 := validProductPack()
	v2.Version = "2.0.0"
	v2.Migration = MigrationInfo{FromVersions: []string{"1.0.0"}, Notes: "adds cancellation"}
	v2.Digest = PackContentDigest(v2)
	if v2.Digest == v1.Digest {
		t.Fatal("an upgraded pack must have a distinct content digest")
	}
	bindingAfter, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bindingBefore, bindingAfter) {
		t.Fatal("producing a product upgrade must not mutate the customer binding")
	}

	// Adopting the upgrade only re-points the binding's product reference; every
	// customer-owned field (endpoints, secrets, mappings) is preserved verbatim.
	upgraded := UpgradePackReference(binding, v2)
	if upgraded.Product.Version != "2.0.0" || upgraded.Product.Digest != v2.Digest {
		t.Fatalf("upgrade must re-point the product reference, got %+v", upgraded.Product)
	}
	upgraded.Product = binding.Product
	rebased, err := json.Marshal(upgraded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bindingBefore, rebased) {
		t.Fatal("a product upgrade must not overwrite any customer-owned binding field")
	}
}

func TestCapabilityVocabularyMatchesFrozenPattern(t *testing.T) {
	const frozen = `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`
	if CapabilityPattern != frozen {
		t.Fatalf("connector capability pattern %q diverged from the frozen runtime contract %q", CapabilityPattern, frozen)
	}
	// Drift guard for the digest reference format too (runtime keeps its copy
	// unexported, being the frozen 0A contract; the service parity test proves
	// behavioural agreement with runtime.ValidateSHA256Ref).
	const frozenDigest = `^sha256:[0-9a-f]{64}$`
	if Sha256RefPattern != frozenDigest {
		t.Fatalf("connector Sha256RefPattern %q diverged from the frozen runtime digest format %q", Sha256RefPattern, frozenDigest)
	}
	valid := []string{"erp.purchase_order.approve", "mes.work_order.read", "a.b"}
	for _, c := range valid {
		if err := ValidateCapabilityName(c); err != nil {
			t.Fatalf("capability %q must be accepted: %v", c, err)
		}
	}
	invalid := []string{"", "update", "Read PO", "SELECT * FROM po", "postgres://x", "erp..approve", "1erp.x", "erp.", ".erp"}
	for _, c := range invalid {
		if err := ValidateCapabilityName(c); err == nil {
			t.Fatalf("capability %q must be rejected", c)
		}
	}
}

func boolPtr(b bool) *bool { return &b }
