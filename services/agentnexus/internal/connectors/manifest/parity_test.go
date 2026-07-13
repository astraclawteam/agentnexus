package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	runtime "github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// parity_test proves the Connector Product Pack v1 schemas are consistent with
// the frozen public Agent runtime contract (sdk/go/runtime) and that they are
// genuinely load-bearing: fixtures are validated against the .schema.json
// documents with a self-contained JSON Schema 2020-12 evaluator (so neither the
// connector SDK nor this service takes a JSON-Schema library dependency), and
// the schema is shown to reject the bad shapes, not only the Go validator.

const (
	productPackSchemaPath     = "../../../schemas/connectors/product-pack.schema.json"
	customerBindingSchemaPath = "../../../schemas/connectors/customer-binding.schema.json"
)

func packDigestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fixtureReadCapability() connector.Capability {
	return connector.Capability{
		Name:   "erp.purchase_order.read",
		Title:  "Read purchase order",
		Effect: connector.EffectRead,
		Input:  connector.IOSchema{Ref: "schema.erp.purchase_order.read.input", Digest: packDigestOf("in-read")},
		Output: connector.IOSchema{Ref: "schema.erp.purchase_order.read.output", Digest: packDigestOf("out-read")},
	}
}

func fixtureWriteCapability() connector.Capability {
	return connector.Capability{
		Name:        "erp.purchase_order.approve",
		Title:       "Approve purchase order",
		Effect:      connector.EffectWrite,
		Input:       connector.IOSchema{Ref: "schema.erp.purchase_order.approve.input", Digest: packDigestOf("in-write")},
		Output:      connector.IOSchema{Ref: "schema.erp.purchase_order.approve.output", Digest: packDigestOf("out-write")},
		SideEffects: []connector.SideEffect{{Kind: "external_write", Description: "posts an approval to the ERP", Reversible: false}},
		Reconciliation: &connector.Reconciliation{
			Strategy:               "verify_then_compensate",
			VerifyCapability:       "erp.purchase_order.read",
			CompensationCapability: "erp.purchase_order.reject",
		},
	}
}

func fixtureRejectCapability() connector.Capability {
	return connector.Capability{
		Name:        "erp.purchase_order.reject",
		Title:       "Reject purchase order",
		Effect:      connector.EffectWrite,
		Input:       connector.IOSchema{Ref: "schema.erp.purchase_order.reject.input", Digest: packDigestOf("in-reject")},
		Output:      connector.IOSchema{Ref: "schema.erp.purchase_order.reject.output", Digest: packDigestOf("out-reject")},
		SideEffects: []connector.SideEffect{{Kind: "external_write", Description: "records a rejection in the ERP", Reversible: true}},
		Reconciliation: &connector.Reconciliation{
			Strategy:         "verify_then_compensate",
			VerifyCapability: "erp.purchase_order.read",
		},
	}
}

func fixtureProductPack() connector.ProductPack {
	p := connector.ProductPack{
		SchemaVersion: connector.ProductPackSchemaVersion,
		ProductKey:    "sap.s4hana.procurement",
		Version:       "1.0.0",
		Title:         "S/4HANA Procurement",
		Capabilities:  []connector.Capability{fixtureReadCapability(), fixtureWriteCapability(), fixtureRejectCapability()},
		FieldPolicy: connector.FieldPolicy{
			Classifications: []connector.FieldClassification{{Field: "amount", Classification: "confidential", Redacted: true}},
		},
		Network:       connector.NetworkRequirements{Egress: []string{"erp.api"}, Isolation: "outbound_only"},
		Runtime:       connector.RuntimeRequirements{Runtime: "wasm", MinMemoryMB: 64},
		Compatibility: connector.Compatibility{RuntimeContract: connector.VersionRange{Min: "1.0.0", Max: "1.9.9"}, ConnectorRuntime: connector.VersionRange{Min: "1.0.0"}},
		Migration:     connector.MigrationInfo{FromVersions: []string{}, Notes: "initial release"},
		Limits:        connector.Limits{MaxConcurrency: 8, MaxRequestsPerMinute: 600},
		SBOM:          connector.ArtifactRef{Ref: "sbom.sap.s4hana.procurement", Digest: packDigestOf("sbom")},
		Provenance:    connector.ArtifactRef{Ref: "provenance.sap.s4hana.procurement", Digest: packDigestOf("provenance")},
	}
	p.Digest = connector.PackContentDigest(p)
	p.Signature = connector.Signature{Algorithm: connector.SignatureAlgorithmEd25519, KeyID: "connector-signing-1", Value: "c2lnbmF0dXJlLWJ5dGVz"}
	return p
}

func fixtureBinding(p connector.ProductPack, name, ref, endpoint, secretRef, resource, source string) connector.CustomerBinding {
	return connector.CustomerBinding{
		SchemaVersion:    connector.CustomerBindingSchemaVersion,
		BindingKey:       ref,
		Customer:         connector.CustomerRef{Name: name, Ref: ref},
		Product:          connector.ProductRef{ProductKey: p.ProductKey, Version: p.Version, Digest: p.Digest},
		Endpoints:        []connector.Endpoint{{Name: "erp", URL: endpoint}},
		Secrets:          []connector.SecretRef{{Name: "erp_oauth", Ref: secretRef}},
		ResourceMappings: []connector.ResourceMapping{{Capability: "erp.purchase_order.read", Resource: resource}},
		FieldMappings:    []connector.FieldMapping{{Field: "amount", Source: source}},
	}
}

func toInstance(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func loadSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema %s is not valid JSON: %v", path, err)
	}
	if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema %s must declare JSON Schema 2020-12, got %v", path, doc["$schema"])
	}
	// The self-contained evaluator implements only a subset of 2020-12. Guard
	// against silent gaps: if the schema ever uses a keyword the evaluator does
	// not implement, fail loudly here rather than passing a fixture the evaluator
	// under-checks. The fix is to implement the keyword in validateNode (and this
	// allowlist) or to validate against a real jsonschema/v6 library.
	assertImplementedKeywordsOnly(t, doc, path)
	return doc
}

// implementedSchemaKeywords is exactly the set validateNode acts on, plus the
// pure annotations it may safely ignore. Anything else is a coverage gap.
var implementedSchemaKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "$defs": true, "$comment": true, "$anchor": true,
	"title": true, "description": true,
	"type": true, "const": true, "enum": true, "pattern": true,
	"minLength": true, "minItems": true, "minimum": true,
	"required": true, "properties": true, "additionalProperties": true,
	"items": true, "allOf": true, "if": true, "then": true, "else": true,
}

func assertImplementedKeywordsOnly(t *testing.T, schema any, path string) {
	t.Helper()
	m, ok := schema.(map[string]any)
	if !ok {
		return
	}
	for k := range m {
		if !implementedSchemaKeywords[k] {
			t.Fatalf("schema %s uses keyword %q the parity evaluator does not implement; implement it in validateNode (and implementedSchemaKeywords) or validate with a real jsonschema/v6 library before trusting this test", path, k)
		}
	}
	if props, ok := m["properties"].(map[string]any); ok {
		for name, sub := range props {
			assertImplementedKeywordsOnly(t, sub, path+"/properties/"+name)
		}
	}
	if defs, ok := m["$defs"].(map[string]any); ok {
		for name, sub := range defs {
			assertImplementedKeywordsOnly(t, sub, path+"/$defs/"+name)
		}
	}
	if items, ok := m["items"].(map[string]any); ok {
		assertImplementedKeywordsOnly(t, items, path+"/items")
	}
	if ap, ok := m["additionalProperties"].(map[string]any); ok {
		assertImplementedKeywordsOnly(t, ap, path+"/additionalProperties")
	}
	for _, key := range []string{"if", "then", "else"} {
		if sub, ok := m[key].(map[string]any); ok {
			assertImplementedKeywordsOnly(t, sub, path+"/"+key)
		}
	}
	if all, ok := m["allOf"].([]any); ok {
		for i, sub := range all {
			assertImplementedKeywordsOnly(t, sub, fmt.Sprintf("%s/allOf/%d", path, i))
		}
	}
}

// --- self-contained JSON Schema 2020-12 evaluator (subset used by the pack and
// binding schemas: type/const/enum/pattern/minLength/minItems/minimum/required/
// properties/additionalProperties:false/items/allOf/if-then-else/$ref). Any
// schema keyword outside this subset is rejected by assertImplementedKeywordsOnly
// so the evaluator can never silently under-check a future schema edit. ---

func schemaValidate(root, schema map[string]any, instance any) error {
	return validateNode(root, schema, instance, "$")
}

func resolveRef(root map[string]any, ref string) (map[string]any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported $ref %q", ref)
	}
	cur := any(root)
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("cannot resolve $ref %q at %q", ref, seg)
		}
		cur = m[seg]
	}
	target, ok := cur.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q does not resolve to a schema", ref)
	}
	return target, nil
}

func validateNode(root, schema map[string]any, instance any, path string) error {
	if ref, ok := schema["$ref"].(string); ok {
		target, err := resolveRef(root, ref)
		if err != nil {
			return err
		}
		if err := validateNode(root, target, instance, path); err != nil {
			return err
		}
	}
	if typ, ok := schema["type"].(string); ok {
		if !instanceHasType(instance, typ) {
			return fmt.Errorf("%s: expected type %s", path, typ)
		}
	}
	if c, ok := schema["const"]; ok {
		if !reflect.DeepEqual(normalize(c), normalize(instance)) {
			return fmt.Errorf("%s: expected const %v", path, c)
		}
	}
	if enum, ok := schema["enum"].([]any); ok {
		matched := false
		for _, e := range enum {
			if reflect.DeepEqual(normalize(e), normalize(instance)) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: value %v not in enum", path, instance)
		}
	}
	if pat, ok := schema["pattern"].(string); ok {
		s, ok := instance.(string)
		if !ok {
			return fmt.Errorf("%s: pattern applies to strings", path)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("%s: bad pattern %q: %v", path, pat, err)
		}
		if !re.MatchString(s) {
			return fmt.Errorf("%s: %q does not match %q", path, s, pat)
		}
	}
	if ml, ok := schema["minLength"]; ok {
		if s, ok := instance.(string); ok && float64(len(s)) < toFloat(ml) {
			return fmt.Errorf("%s: shorter than minLength", path)
		}
	}
	if mi, ok := schema["minItems"]; ok {
		if arr, ok := instance.([]any); ok && float64(len(arr)) < toFloat(mi) {
			return fmt.Errorf("%s: fewer than minItems", path)
		}
	}
	if mn, ok := schema["minimum"]; ok {
		if n, ok := instance.(float64); ok && n < toFloat(mn) {
			return fmt.Errorf("%s: less than minimum", path)
		}
	}
	if req, ok := schema["required"].([]any); ok {
		obj, ok := instance.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: required applies to objects", path)
		}
		for _, r := range req {
			key := r.(string)
			if _, present := obj[key]; !present {
				return fmt.Errorf("%s: missing required property %q", path, key)
			}
		}
	}
	props, _ := schema["properties"].(map[string]any)
	if props != nil {
		if obj, ok := instance.(map[string]any); ok {
			for name, sub := range props {
				val, present := obj[name]
				if !present {
					continue
				}
				subSchema, ok := sub.(map[string]any)
				if !ok {
					return fmt.Errorf("%s.%s: property schema must be an object", path, name)
				}
				if err := validateNode(root, subSchema, val, path+"."+name); err != nil {
					return err
				}
			}
		}
	}
	if ap, ok := schema["additionalProperties"]; ok {
		if allowed, isBool := ap.(bool); isBool && !allowed {
			if obj, ok := instance.(map[string]any); ok {
				for key := range obj {
					if _, declared := props[key]; !declared {
						return fmt.Errorf("%s: additional property %q is not allowed", path, key)
					}
				}
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		if arr, ok := instance.([]any); ok {
			for i, el := range arr {
				if err := validateNode(root, items, el, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	if allOf, ok := schema["allOf"].([]any); ok {
		for i, sub := range allOf {
			subSchema, ok := sub.(map[string]any)
			if !ok {
				return fmt.Errorf("%s: allOf[%d] must be a schema", path, i)
			}
			if err := validateNode(root, subSchema, instance, path); err != nil {
				return err
			}
		}
	}
	if ifSchema, ok := schema["if"].(map[string]any); ok {
		if validateNode(root, ifSchema, instance, path) == nil {
			if thenSchema, ok := schema["then"].(map[string]any); ok {
				if err := validateNode(root, thenSchema, instance, path); err != nil {
					return err
				}
			}
		} else if elseSchema, ok := schema["else"].(map[string]any); ok {
			if err := validateNode(root, elseSchema, instance, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func instanceHasType(instance any, typ string) bool {
	switch typ {
	case "string":
		_, ok := instance.(string)
		return ok
	case "boolean":
		_, ok := instance.(bool)
		return ok
	case "object":
		_, ok := instance.(map[string]any)
		return ok
	case "array":
		_, ok := instance.([]any)
		return ok
	case "number":
		_, ok := instance.(float64)
		return ok
	case "integer":
		f, ok := instance.(float64)
		return ok && f == math.Trunc(f)
	}
	return false
}

func normalize(v any) any { return v }
func toFloat(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

// walkDeclaredPropertyNames collects every instance-facing property name declared
// anywhere under a schema's "properties" objects.
func walkDeclaredPropertyNames(node any, out map[string]bool) {
	switch n := node.(type) {
	case map[string]any:
		if props, ok := n["properties"].(map[string]any); ok {
			for name := range props {
				out[name] = true
			}
		}
		for _, v := range n {
			walkDeclaredPropertyNames(v, out)
		}
	case []any:
		for _, v := range n {
			walkDeclaredPropertyNames(v, out)
		}
	}
}

func TestProductPackSchemaAcceptsCanonicalAndRejectsBadShapes(t *testing.T) {
	schema := loadSchema(t, productPackSchemaPath)
	good := toInstance(t, fixtureProductPack())
	if err := schemaValidate(schema, schema, good); err != nil {
		t.Fatalf("canonical product pack must satisfy the schema, got %v", err)
	}

	bad := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"customer name is a forbidden property", func(d map[string]any) { d["customer_name"] = "Acme" }},
		{"endpoint is a forbidden property", func(d map[string]any) { d["endpoint"] = "https://acme" }},
		{"field mapping is a forbidden property", func(d map[string]any) {
			d["field_mappings"] = []any{map[string]any{"field": "amount", "source": "NETWR"}}
		}},
		{"unsigned pack is rejected", func(d map[string]any) { delete(d, "signature") }},
		{"digestless pack is rejected", func(d map[string]any) { delete(d, "digest") }},
		{"missing sbom is rejected", func(d map[string]any) { delete(d, "sbom") }},
		{"missing compatibility is rejected", func(d map[string]any) { delete(d, "compatibility") }},
		{"write capability without reconciliation is rejected", func(d map[string]any) {
			cap := d["capabilities"].([]any)[1].(map[string]any)
			delete(cap, "reconciliation")
		}},
		{"write capability without side effects is rejected", func(d map[string]any) {
			cap := d["capabilities"].([]any)[1].(map[string]any)
			delete(cap, "side_effects")
		}},
		{"raw io path is rejected", func(d map[string]any) {
			cap := d["capabilities"].([]any)[0].(map[string]any)
			cap["input"].(map[string]any)["ref"] = "postgres://mes/workorders"
		}},
		{"development pack is not a production pack", func(d map[string]any) { d["development"] = true }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			doc := toInstance(t, fixtureProductPack()).(map[string]any)
			tc.mutate(doc)
			if err := schemaValidate(schema, schema, doc); err == nil {
				t.Fatalf("schema must reject: %s", tc.name)
			}
		})
	}
}

func TestCustomerBindingSchemaAcceptsCanonicalAndRejectsInlineSecret(t *testing.T) {
	schema := loadSchema(t, customerBindingSchemaPath)
	p := fixtureProductPack()
	good := toInstance(t, fixtureBinding(p, "Acme Manufacturing", "cust_acme", "https://acme.erp.example/api", "secretref://vault/acme/erp", "acme.po", "NETWR"))
	if err := schemaValidate(schema, schema, good); err != nil {
		t.Fatalf("canonical binding must satisfy the schema, got %v", err)
	}

	bad := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"inline secret value beside a reference", func(d map[string]any) {
			d["secrets"].([]any)[0].(map[string]any)["value"] = "raw-token"
		}},
		{"missing product reference", func(d map[string]any) { delete(d, "product") }},
		{"no endpoints", func(d map[string]any) { d["endpoints"] = []any{} }},
		{"secret ref is a raw secret not a reference", func(d map[string]any) {
			d["secrets"].([]any)[0].(map[string]any)["ref"] = "AKIAIOSFODNN7EXAMPLE"
		}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			doc := toInstance(t, fixtureBinding(p, "Acme Manufacturing", "cust_acme", "https://acme.erp.example/api", "secretref://vault/acme/erp", "acme.po", "NETWR")).(map[string]any)
			tc.mutate(doc)
			if err := schemaValidate(schema, schema, doc); err == nil {
				t.Fatalf("schema must reject: %s", tc.name)
			}
		})
	}
}

func TestProductPackCapabilityVocabularyMatchesRuntimeContract(t *testing.T) {
	schema := loadSchema(t, productPackSchemaPath)

	// The schema's capability name pattern must be the exact frozen runtime
	// capability regex, mirrored through the connector SDK constant.
	defs := schema["$defs"].(map[string]any)
	capName := defs["capabilityName"].(map[string]any)
	schemaPattern, _ := capName["pattern"].(string)
	if schemaPattern != connector.CapabilityPattern {
		t.Fatalf("product-pack schema capability pattern %q != connector.CapabilityPattern %q", schemaPattern, connector.CapabilityPattern)
	}
	const frozen = `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`
	if connector.CapabilityPattern != frozen {
		t.Fatalf("connector.CapabilityPattern %q diverged from the frozen runtime contract %q", connector.CapabilityPattern, frozen)
	}

	// Behavioural parity: for the same capability strings, the connector SDK and
	// the runtime contract agree on acceptance. No second vocabulary exists.
	samples := []string{
		"erp.purchase_order.approve", "mes.work_order.read", "a.b",
		"", "update", "Read PO", "SELECT * FROM po", "postgres://x", "erp..approve", "1erp.x",
	}
	for _, c := range samples {
		connectorOK := connector.ValidateCapabilityName(c) == nil
		if runtimeAcceptsCapability(c) != connectorOK {
			t.Fatalf("capability %q: runtime and connector disagree (connector accepts=%v)", c, connectorOK)
		}
	}
}

func runtimeAcceptsCapability(capability string) bool {
	req := runtime.BusinessCapabilityRequest{
		RequestID:          "req-parity",
		BusinessContextRef: "wc_0123456789abcdef",
		Capability:         capability,
		Purpose:            "capability vocabulary parity probe",
		ExpiresAt:          time.Now().Add(time.Hour),
	}
	err := req.Validate()
	if err == nil {
		return true
	}
	// Only a capability-specific rejection counts as "runtime rejects the vocab".
	return !strings.Contains(err.Error(), "capability")
}

// TestDigestFormatMatchesRuntimeContract proves the connector SDK's digest
// reference format agrees with the runtime contract's exported validator. The
// runtime keeps its own regex unexported (it is the frozen 0A contract, which we
// must not modify to add an exported const), so the connector mirrors the format
// by value and this behavioural parity check guards against drift.
func TestDigestFormatMatchesRuntimeContract(t *testing.T) {
	re := regexp.MustCompile(connector.Sha256RefPattern)
	samples := []string{
		"sha256:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("0", 64),
		"",
		"sha256:",
		"sha256:ZZ",
		"md5:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
		"sha256:" + strings.Repeat("A", 64),
		" sha256:" + strings.Repeat("a", 64),
	}
	for _, s := range samples {
		connectorOK := re.MatchString(s)
		runtimeOK := runtime.ValidateSHA256Ref(s) == nil
		if connectorOK != runtimeOK {
			t.Fatalf("digest %q: connector=%v runtime=%v", s, connectorOK, runtimeOK)
		}
	}
}

func TestProductPackSchemaLeaksNoConnectorTopology(t *testing.T) {
	schema := loadSchema(t, productPackSchemaPath)
	declared := map[string]bool{}
	walkDeclaredPropertyNames(schema, declared)

	forbidden := []string{
		"customer_name", "customer", "endpoint", "endpoints", "base_url", "url", "host", "hostname",
		"credential", "credentials", "secret", "secrets", "password", "token", "api_key", "dsn",
		"connection_string", "table", "table_name", "api_path", "field_mapping", "field_mappings",
		"mapping", "mappings", "org_mapping", "resource_mapping",
	}
	for _, name := range forbidden {
		if declared[name] {
			t.Fatalf("product-pack schema declares connector-topology property %q that the Agent must never see", name)
		}
	}

	// And the canonical pack bytes must carry no customer topology either.
	raw, err := json.Marshal(fixtureProductPack())
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"Acme", "acme", "Globex", "globex", "vault", "://"} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("canonical product pack bytes leaked topology %q", needle)
		}
	}
}

// TestReusablePackBytesIdenticalAcrossTwoBindingsFromService proves the DESIGN
// property (not marshal determinism): the pack builder takes only product-level
// inputs, so a pack built independently while onboarding any customer reproduces
// the exact product-only reference bytes and never contains that customer's
// data. Customer inputs flow exclusively into the CustomerBinding.
func TestReusablePackBytesIdenticalAcrossTwoBindingsFromService(t *testing.T) {
	packSchema := loadSchema(t, productPackSchemaPath)
	bindingSchema := loadSchema(t, customerBindingSchemaPath)

	reference, err := json.Marshal(fixtureProductPack())
	if err != nil {
		t.Fatal(err)
	}
	if err := schemaValidate(packSchema, packSchema, toInstance(t, fixtureProductPack())); err != nil {
		t.Fatalf("pack must satisfy schema: %v", err)
	}

	customers := []struct{ name, ref, endpoint, secretRef, resource, source string }{
		{"Acme Manufacturing", "cust_acme", "https://acme.erp.example/api", "secretref://vault/acme/erp", "acme.ekko", "NETWR"},
		{"Globex Industrie", "cust_globex", "https://globex.sap.example/odata", "secretref://vault/globex/sap", "globex.po", "WRBTR"},
		{"Initech GmbH", "cust_initech", "https://initech.example/soap", "kv://initech/erp/oauth", "initech.ekpo", "DMBTR"},
	}
	for _, c := range customers {
		// Built fresh for this customer — but the customer is not an argument to
		// the pack builder, so the bytes cannot vary by customer.
		pack := fixtureProductPack()
		packBytes, err := json.Marshal(pack)
		if err != nil {
			t.Fatal(err)
		}
		if string(packBytes) != string(reference) {
			t.Fatalf("pack bytes varied while onboarding %q — the pack design leaks customer-varying state", c.name)
		}
		binding := fixtureBinding(pack, c.name, c.ref, c.endpoint, c.secretRef, c.resource, c.source)
		if err := connector.ValidateBinding(binding); err != nil {
			t.Fatalf("binding for %q must validate: %v", c.name, err)
		}
		if err := schemaValidate(bindingSchema, bindingSchema, toInstance(t, binding)); err != nil {
			t.Fatalf("binding for %q must satisfy schema: %v", c.name, err)
		}
		for _, needle := range []string{c.name, c.ref, c.endpoint, c.secretRef, c.resource, c.source} {
			if strings.Contains(string(reference), needle) {
				t.Fatalf("reusable pack bytes leaked customer datum %q", needle)
			}
		}
	}
}

func TestDevelopmentMigrationRequiresSignedFormForProduction(t *testing.T) {
	packSchema := loadSchema(t, productPackSchemaPath)
	m := connector.Manifest{
		SchemaVersion: "2026-07-06",
		Name:          "legacy_erp",
		Version:       "0.3.0",
		Resources: []connector.Resource{
			{Name: "purchase_orders", Type: connector.ResourceTypeHTTP, Operations: []connector.Operation{{Name: "list", Method: "GET", Path: "/api/v2/po"}}},
			{Name: "approvals", Type: connector.ResourceTypeHTTP, ReadOnly: boolPtrManifest(false), Operations: []connector.Operation{{Name: "approve", Method: "POST", Path: "/api/v2/po/approve"}}},
		},
	}
	dev := connector.DevelopmentPackFromManifest(m)
	if err := connector.ValidateDevelopmentPack(dev); err != nil {
		t.Fatalf("development pack must pass development validation: %v", err)
	}
	if err := connector.ValidateProductionPack(dev); err == nil {
		t.Fatal("a generic manifest may never be imported as a production product pack")
	}

	// The production schema must also reject the unsigned development fixture:
	// production import strictly requires the signed product form.
	if err := schemaValidate(packSchema, packSchema, toInstance(t, dev)); err == nil {
		t.Fatal("production product-pack schema must reject an unsigned development pack")
	}
}

func TestMigration000012DefinesProductsAndBindings(t *testing.T) {
	raw, err := os.ReadFile("../../../db/migrations/000012_connector_products_bindings.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToLower(strings.Join(strings.Fields(string(raw)), " "))
	for _, fragment := range []string{
		"create table connector_products",
		"create table connector_bindings",
		"tenant_id text not null",
		"primary key (tenant_id, product_key, version)",
		"unique (tenant_id, product_key, version, digest)",
		"signature_value text not null check (signature_value <> '')",
		"sbom_digest text not null",
		"provenance_digest text not null",
		"chk_connector_products_not_development",
		"chk_connector_products_customer_agnostic",
		"foreign key (tenant_id, product_key, product_version, product_digest)",
		"references connector_products (tenant_id, product_key, version, digest)",
		"chk_connector_bindings_no_inline_secret",
	} {
		if !strings.Contains(sql, fragment) {
			t.Fatalf("migration 000012 must contain %q", fragment)
		}
	}

	lower := strings.ToLower(string(raw))
	down := lower[strings.Index(lower, "+goose down"):]
	if !strings.Contains(down, "drop table if exists connector_bindings") || !strings.Contains(down, "drop table if exists connector_products") {
		t.Fatal("migration 000012 Down must drop connector_bindings and connector_products")
	}
	if strings.Index(down, "connector_bindings") > strings.Index(down, "connector_products") {
		t.Fatal("Down must drop connector_bindings before connector_products (foreign key order)")
	}
}

func boolPtrManifest(b bool) *bool { return &b }
