package app

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPublicContractParity freezes the vendor-neutral Agent runtime contract
// (GA Task 0A, ELC-NEXUS-1 candidate) across the ACTUAL public contract
// artifacts: api/openapi/gateway-runtime.yaml, api/openapi/gateway-agent.yaml
// and the public protobuf packages evidence/v1, actions/v1, trust/v1 and
// audit/v1.
//
// Frozen boundaries proven here:
//   - trusted identity (enterprise_id, actor_user_id) and connector topology
//     (connector_instance_id, connector_* selectors, resource_name) never
//     appear in public request/response schemas;
//   - no AgentAtlas-specific name remains in the generic public contract;
//   - actions are typed: semantic capability + parameters + parameter hash;
//     the legacy untyped `action` + `input` pair is gone;
//   - RiskDecision is signed and bound to the exact operation;
//   - ActionRequest carries an idempotency key and expiry;
//   - Step Grants bind to one exact operation (capability + parameter hash +
//     one-use);
//   - connector topology stays in connector-internal messages
//     (connectors/v1), never in Agent-facing messages;
//   - request bodies never supply trusted organization facts (org_version /
//     org_unit_id); responses may expose the server-authored sealed snapshot
//     version;
//   - (GA Task 0A amendment, plan dc81e80) the public surface REQUIRES
//     PostconditionSpec, VerificationNeed and a signed ObservationReceipt
//     bound to source/version, authority, observed-at/freshness and the
//     original Action/Postcondition, and REJECTS any `outcome`,
//     `goal_achieved` or graph-provider field name: ActionReceipt attests
//     technical execution only, ObservationReceipt proves a bounded
//     authoritative observation, and neither carries a business Outcome
//     assertion.
//
// Scope note: tasks/v1/tasks.proto (internal orchestration state) and
// api/openapi/console-overview.yaml (console-internal surface) retain legacy
// identity fields on purpose; their rework is deferred to Tasks 0B/0F and
// they are deliberately outside this public parity scope. connectors/v1 is
// the connector-internal plane and keeps its topology fields by design.

const sha256RefPattern = `^sha256:[0-9a-f]{64}$`

var publicProtoFiles = []string{
	filepath.Join("evidence", "v1", "evidence.proto"),
	filepath.Join("actions", "v1", "actions.proto"),
	filepath.Join("trust", "v1", "trust.proto"),
	filepath.Join("audit", "v1", "audit.proto"),
}

// frozenActionStates is the exact frozen Action lifecycle (implemented by GA
// Task 0F; frozen by Task 0A).
var frozenActionStates = []string{
	"requested", "awaiting_approval", "granted", "dispatched", "executing",
	"succeeded", "failed", "result_unknown", "reconciling", "compensating",
	"human_takeover",
}

func openAPIPath(name string) string {
	return filepath.Join("..", "..", "api", "openapi", name)
}

func protoPath(rel string) string {
	return filepath.Join("..", "..", "api", "proto", "agentnexus", rel)
}

func loadPublicOpenAPI(t *testing.T, name string) (map[string]any, string) {
	t.Helper()
	raw, err := os.ReadFile(openAPIPath(name))
	if err != nil {
		t.Fatalf("read public contract %s: %v", name, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("public contract %s is not well-formed YAML: %v", name, err)
	}
	return doc, string(raw)
}

// forbiddenPublicFieldName reports why a schema property name is prohibited
// anywhere in the public contract, or "" when it is allowed.
//
// org_version is deliberately NOT in this global set: the server-authored
// sealed snapshot version is a legitimate RESPONSE field (BrowserSession,
// PermissionDecision). Its request-side ban is enforced by
// NoCallerSuppliedOrgFactsInRequestBodies.
//
// The business-outcome and graph-provider bans (GA Task 0A amendment, plan
// dc81e80) freeze the authority boundary: ActionReceipt attests technical
// execution only, ObservationReceipt proves a bounded authoritative
// observation, AgentNexus never decides whether a business Outcome/goal was
// achieved and never owns or queries the calling Agent platform's result
// graph. Like every check in this function, the ban targets schema/field/
// property NAMES (OpenAPI properties and required entries, proto field
// names), never prose descriptions.
func forbiddenPublicFieldName(name string) string {
	switch name {
	case "enterprise_id", "actor_user_id":
		return "caller-supplied trusted identity"
	case "connector_instance_id":
		return "connector topology"
	case "resource_name":
		return "connector-specific resource selector"
	case "org_unit_id":
		return "caller-supplied trusted organization scope"
	}
	if strings.Contains(name, "enterprise") {
		return "tenant identity leak"
	}
	if strings.HasPrefix(name, "connector_") {
		return "connector topology"
	}
	if strings.Contains(name, "outcome") || strings.Contains(name, "goal_achieved") {
		return "business-outcome authority leak (AgentNexus never authors Outcomes)"
	}
	if name == "graph" || strings.HasPrefix(name, "graph_") || strings.HasSuffix(name, "_graph") {
		return "graph-provider leak (the result graph belongs to the calling Agent platform)"
	}
	return ""
}

// walkYAML visits every node of a decoded YAML document. A node with
// non-string keys fails LOUDLY: silently skipping it would let a forbidden
// field hide behind an exotic key type.
func walkYAML(t *testing.T, node any, path string, visit func(path string, node any)) {
	t.Helper()
	if _, nonString := node.(map[any]any); nonString {
		t.Fatalf("YAML node %s decoded with non-string keys; the frozen contract documents must use plain string keys", path)
	}
	visit(path, node)
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			walkYAML(t, child, path+"/"+key, visit)
		}
	case []any:
		for i, child := range v {
			walkYAML(t, child, fmt.Sprintf("%s[%d]", path, i), visit)
		}
	}
}

// schemaPropertyNames collects every declared property name and every
// required-list entry across the whole document (components and inline path
// schemas alike).
func schemaPropertyNames(t *testing.T, doc map[string]any) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	walkYAML(t, doc, "", func(path string, node any) {
		object, ok := node.(map[string]any)
		if !ok {
			return
		}
		if properties, ok := object["properties"].(map[string]any); ok {
			for name := range properties {
				found[name] = append(found[name], path+"/properties")
			}
		}
		if required, ok := object["required"].([]any); ok {
			for _, entry := range required {
				if name, ok := entry.(string); ok {
					found[name] = append(found[name], path+"/required")
				}
			}
		}
	})
	return found
}

// resolveSchema follows a local $ref chain inside the document.
func resolveSchema(t *testing.T, doc map[string]any, node map[string]any) map[string]any {
	t.Helper()
	for i := 0; i < 10; i++ {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node
		}
		if !strings.HasPrefix(ref, "#/") {
			t.Fatalf("external $ref %q is not allowed in the frozen contract", ref)
		}
		current := any(doc)
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			object, ok := current.(map[string]any)
			if !ok {
				t.Fatalf("$ref %q does not resolve (at %q)", ref, part)
			}
			current, ok = object[part]
			if !ok {
				t.Fatalf("$ref %q does not resolve: missing %q", ref, part)
			}
		}
		node, ok = current.(map[string]any)
		if !ok {
			t.Fatalf("$ref %q resolves to %T, want object", ref, current)
		}
	}
	t.Fatal("$ref chain too deep")
	return nil
}

// composedSchema merges an allOf composition (envelope + body) into a single
// view of properties and required names. Revisiting a $ref inside one
// composition is an allOf/$ref cycle and fails loudly.
func composedSchema(t *testing.T, doc map[string]any, schema map[string]any) (map[string]any, map[string]bool) {
	t.Helper()
	properties := map[string]any{}
	required := map[string]bool{}
	visitedRefs := map[string]bool{}
	var merge func(node map[string]any)
	merge = func(node map[string]any) {
		if ref, ok := node["$ref"].(string); ok {
			if visitedRefs[ref] {
				t.Fatalf("allOf/$ref cycle through %q", ref)
			}
			visitedRefs[ref] = true
		}
		node = resolveSchema(t, doc, node)
		if all, ok := node["allOf"].([]any); ok {
			for _, part := range all {
				object, ok := part.(map[string]any)
				if !ok {
					t.Fatalf("allOf entry is %T, want object", part)
				}
				merge(object)
			}
		}
		if props, ok := node["properties"].(map[string]any); ok {
			for name, child := range props {
				properties[name] = child
			}
		}
		if requiredList, ok := node["required"].([]any); ok {
			for _, entry := range requiredList {
				if name, ok := entry.(string); ok {
					required[name] = true
				}
			}
		}
	}
	merge(schema)
	return properties, required
}

// deepSchemaNodes returns every schema object reachable from schema through
// properties, items, additionalProperties and allOf/oneOf/anyOf composition,
// following local $refs at most once each (cycle bound).
func deepSchemaNodes(t *testing.T, doc map[string]any, schema map[string]any) []map[string]any {
	t.Helper()
	var nodes []map[string]any
	visitedRefs := map[string]bool{}
	var collect func(node map[string]any)
	collect = func(node map[string]any) {
		if ref, ok := node["$ref"].(string); ok {
			if visitedRefs[ref] {
				return
			}
			visitedRefs[ref] = true
			node = resolveSchema(t, doc, node)
		}
		nodes = append(nodes, node)
		for _, key := range []string{"allOf", "oneOf", "anyOf"} {
			if list, ok := node[key].([]any); ok {
				for _, entry := range list {
					if child, ok := entry.(map[string]any); ok {
						collect(child)
					}
				}
			}
		}
		if properties, ok := node["properties"].(map[string]any); ok {
			for _, value := range properties {
				if child, ok := value.(map[string]any); ok {
					collect(child)
				}
			}
		}
		if items, ok := node["items"].(map[string]any); ok {
			collect(items)
		}
		if additional, ok := node["additionalProperties"].(map[string]any); ok {
			collect(additional)
		}
	}
	collect(schema)
	return nodes
}

func requireProperty(t *testing.T, doc map[string]any, properties map[string]any, name string) map[string]any {
	t.Helper()
	value, ok := properties[name]
	if !ok {
		t.Fatalf("property %q is missing", name)
	}
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("property %q is %T, want object", name, value)
	}
	return resolveSchema(t, doc, object)
}

func sortedNames(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func TestPublicContractParity(t *testing.T) {
	runtimeDoc, runtimeText := loadPublicOpenAPI(t, "gateway-runtime.yaml")
	agentDoc, agentText := loadPublicOpenAPI(t, "gateway-agent.yaml")
	documents := map[string]map[string]any{
		"gateway-runtime.yaml": runtimeDoc,
		"gateway-agent.yaml":   agentDoc,
	}
	texts := map[string]string{
		"gateway-runtime.yaml": runtimeText,
		"gateway-agent.yaml":   agentText,
	}

	t.Run("NoTrustedIdentityOrConnectorTopologyInOpenAPI", func(t *testing.T) {
		for name, doc := range documents {
			for property, sites := range schemaPropertyNames(t, doc) {
				if reason := forbiddenPublicFieldName(property); reason != "" {
					t.Errorf("%s exposes forbidden field %q (%s) at %v", name, property, reason, sites)
				}
			}
		}
	})

	// Caller JSON can never supply trusted organization facts: no request
	// body schema may declare org_version or org_unit_id at ANY nesting depth
	// (local $refs are followed with a cycle bound). The server-authored
	// sealed snapshot version stays legal in responses (BrowserSession,
	// PermissionDecision), so this ban is request-scoped by construction.
	t.Run("NoCallerSuppliedOrgFactsInRequestBodies", func(t *testing.T) {
		requestBodySchemas := 0
		for name, doc := range documents {
			paths := nestedMap(t, doc, "paths")
			for path, pathValue := range paths {
				operations, ok := pathValue.(map[string]any)
				if !ok {
					continue
				}
				for method, operationValue := range operations {
					operation, ok := operationValue.(map[string]any)
					if !ok {
						continue
					}
					requestBody, ok := operation["requestBody"].(map[string]any)
					if !ok {
						continue
					}
					content, ok := requestBody["content"].(map[string]any)
					if !ok {
						continue
					}
					for mediaType, mediaValue := range content {
						media, ok := mediaValue.(map[string]any)
						if !ok {
							continue
						}
						schema, ok := media["schema"].(map[string]any)
						if !ok {
							continue
						}
						requestBodySchemas++
						site := fmt.Sprintf("%s %s %s (%s)", name, method, path, mediaType)
						for _, node := range deepSchemaNodes(t, doc, schema) {
							properties, _ := node["properties"].(map[string]any)
							for _, forbidden := range []string{"org_version", "org_unit_id"} {
								if _, exists := properties[forbidden]; exists {
									t.Errorf("%s request body declares %q; trusted organization facts derive from verified credentials only",
										site, forbidden)
								}
							}
							if requiredList, ok := node["required"].([]any); ok {
								for _, entry := range requiredList {
									if entryName, ok := entry.(string); ok && (entryName == "org_version" || entryName == "org_unit_id") {
										t.Errorf("%s request body requires %q; trusted organization facts derive from verified credentials only",
											site, entryName)
									}
								}
							}
						}
					}
				}
			}
		}
		if requestBodySchemas == 0 {
			t.Fatal("no request body schemas found; the request-scope walker is broken")
		}
	})

	// Response shapes are frozen with the same rigor as requests: the exact
	// property and required sets of Action and ActionReceipt, the opaque
	// receipt_ref linkage (no embedded receipt object) and the receipt fetch
	// operation.
	t.Run("ActionAndReceiptResponsesAreFrozen", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")
		freeze := func(schemaName string, wantProperties, wantRequired []string) {
			schema, ok := schemas[schemaName].(map[string]any)
			if !ok {
				t.Errorf("%s schema missing", schemaName)
				return
			}
			properties, required := composedSchema(t, runtimeDoc, schema)
			var gotProperties []string
			for property := range properties {
				gotProperties = append(gotProperties, property)
			}
			sort.Strings(gotProperties)
			sort.Strings(wantProperties)
			if !equalStrings(gotProperties, wantProperties) {
				t.Errorf("%s properties = %v, want frozen set %v", schemaName, gotProperties, wantProperties)
			}
			gotRequired := sortedNames(required)
			sort.Strings(wantRequired)
			if !equalStrings(gotRequired, wantRequired) {
				t.Errorf("%s required = %v, want frozen set %v", schemaName, gotRequired, wantRequired)
			}
		}
		freeze("Action",
			[]string{"action_ref", "status", "business_context_ref", "capability", "parameter_hash", "grant_ref", "approval_evidence_ref", "receipt_ref", "updated_at"},
			[]string{"action_ref", "status", "business_context_ref", "capability", "parameter_hash"})
		freeze("ActionReceipt",
			[]string{"receipt_ref", "action_ref", "status", "capability", "parameter_hash", "receipt_schema", "result", "result_hash", "issued_at", "signature"},
			[]string{"receipt_ref", "action_ref", "status", "capability", "parameter_hash", "receipt_schema", "issued_at"})

		receiptsPath := nestedMap(t, runtimeDoc, "paths", "/v1/runtime/receipts/{receipt_ref}", "get")
		if receiptsPath["operationId"] != "getRuntimeActionReceipt" {
			t.Errorf("receipt fetch operationId = %v, want getRuntimeActionReceipt", receiptsPath["operationId"])
		}
		response := nestedMap(t, receiptsPath, "responses", "200", "content", "application/json", "schema")
		if response["$ref"] != "#/components/schemas/ActionReceipt" {
			t.Errorf("receipt fetch 200 schema = %v, want ActionReceipt", response["$ref"])
		}
	})

	// The forbidden-name scan itself must reject the business-outcome and
	// graph-provider surface (GA Task 0A amendment, plan dc81e80) while
	// leaving the frozen observation vocabulary legal. This is the positive
	// control proving the NoTrustedIdentity... scans above would catch such
	// a field the moment one appeared in any public schema or proto.
	t.Run("ForbiddenNameScanRejectsOutcomeAndGraphProviderNames", func(t *testing.T) {
		for _, banned := range []string{
			"outcome", "business_outcome", "outcome_status", "goal_achieved",
			"graph", "graph_provider", "graph_ref", "result_graph", "age_graph",
		} {
			if forbiddenPublicFieldName(banned) == "" {
				t.Errorf("forbiddenPublicFieldName(%q) must reject the business-outcome/graph-provider surface", banned)
			}
		}
		for _, legal := range []string{
			"observation_ref", "observation_hash", "observed_at", "fresh_until",
			"source", "source_version", "authority", "decision", "goal_unrelated",
		} {
			if reason := forbiddenPublicFieldName(legal); reason != "" {
				t.Errorf("forbiddenPublicFieldName(%q) = %q; the frozen observation vocabulary must stay legal", legal, reason)
			}
		}
	})

	// PostconditionSpec and VerificationNeed are the declared post-action
	// verification bindings of ActionRequest (contract v1.3.0): a
	// postcondition declares a post-state condition, a verification need
	// binds exactly one declared postcondition to a business-semantic data
	// class (never a connector location).
	t.Run("PostconditionAndVerificationNeedSchemasExist", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")

		post, ok := schemas["PostconditionSpec"].(map[string]any)
		if !ok {
			t.Fatal("PostconditionSpec schema missing from gateway-runtime.yaml")
		}
		postProperties, postRequired := composedSchema(t, runtimeDoc, post)
		for _, want := range []string{"postcondition_id", "kind", "reference"} {
			if !postRequired[want] {
				t.Errorf("PostconditionSpec must require %q, required = %v", want, sortedNames(postRequired))
			}
		}
		if _, ok := postProperties["expected"]; !ok {
			t.Error("PostconditionSpec must declare optional property \"expected\"")
		}

		need, ok := schemas["VerificationNeed"].(map[string]any)
		if !ok {
			t.Fatal("VerificationNeed schema missing from gateway-runtime.yaml")
		}
		needProperties, needRequired := composedSchema(t, runtimeDoc, need)
		for _, want := range []string{"need_id", "postcondition_id", "data_class"} {
			if !needRequired[want] {
				t.Errorf("VerificationNeed must require %q (an unbound verification need is rejected), required = %v", want, sortedNames(needRequired))
			}
		}
		if len(needProperties) == 0 {
			t.Error("VerificationNeed must declare properties")
		}
	})

	// ObservationReceipt is frozen with the same rigor as ActionReceipt: the
	// exact property and required sets of the bounded-observation binding.
	// Every field is REQUIRED — an observation receipt without source/
	// version/authority/freshness or Action/Postcondition binding is not an
	// observation receipt — and the observation content itself stays behind
	// the opaque evidence handle (handle-addressed, like receipt_ref).
	t.Run("ObservationReceiptBindsBoundedAuthoritativeObservation", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")
		schema, ok := schemas["ObservationReceipt"].(map[string]any)
		if !ok {
			t.Fatal("ObservationReceipt schema missing from gateway-runtime.yaml")
		}
		frozen := []string{
			"observation_ref", "action_ref", "parameter_hash", "postcondition_id",
			"verification_need_id", "source", "source_version", "authority",
			"observed_at", "fresh_until", "observation_hash", "evidence_ref",
			"audit_ref_id", "signature",
		}
		properties, required := composedSchema(t, runtimeDoc, schema)
		var gotProperties []string
		for name := range properties {
			gotProperties = append(gotProperties, name)
		}
		sort.Strings(gotProperties)
		wantFrozen := append([]string(nil), frozen...)
		sort.Strings(wantFrozen)
		if !equalStrings(gotProperties, wantFrozen) {
			t.Errorf("ObservationReceipt properties = %v, want frozen set %v", gotProperties, wantFrozen)
		}
		if gotRequired := sortedNames(required); !equalStrings(gotRequired, wantFrozen) {
			t.Errorf("ObservationReceipt required = %v, want every binding required %v", gotRequired, wantFrozen)
		}

		observationRef := requireProperty(t, runtimeDoc, properties, "observation_ref")
		if pattern, _ := observationRef["pattern"].(string); !strings.HasPrefix(pattern, "^obs_") {
			t.Errorf("observation_ref pattern = %q, want an opaque obs_ handle", pattern)
		}
		for _, hashProperty := range []string{"parameter_hash", "observation_hash"} {
			hash := requireProperty(t, runtimeDoc, properties, hashProperty)
			if hash["pattern"] != sha256RefPattern {
				t.Errorf("%s pattern = %v, want %q", hashProperty, hash["pattern"], sha256RefPattern)
			}
		}
		evidenceRef := requireProperty(t, runtimeDoc, properties, "evidence_ref")
		if pattern, _ := evidenceRef["pattern"].(string); !strings.HasPrefix(pattern, "^evd_") {
			t.Errorf("evidence_ref pattern = %q, want an opaque evd_ handle", pattern)
		}
		for _, timeProperty := range []string{"observed_at", "fresh_until"} {
			bound := requireProperty(t, runtimeDoc, properties, timeProperty)
			if bound["format"] != "date-time" {
				t.Errorf("%s format = %v, want date-time (the observation is bounded in time)", timeProperty, bound["format"])
			}
		}
		sourceVersion := requireProperty(t, runtimeDoc, properties, "source_version")
		if sourceVersion["type"] != "integer" {
			t.Errorf("source_version type = %v, want integer", sourceVersion["type"])
		}
		signature := requireProperty(t, runtimeDoc, properties, "signature")
		_, signatureRequired := composedSchema(t, runtimeDoc, signature)
		for _, want := range []string{"algorithm", "key_id", "value"} {
			if !signatureRequired[want] {
				t.Errorf("ObservationReceipt signature must require %q (an unsigned observation receipt is rejected)", want)
			}
		}
	})

	// The verification-purpose read binding (contract v1.4.0, GA Task 0D
	// amendment, deferral recorded in the task-0d handoff): an
	// EvidenceReadRequest may carry ONE optional VerificationBinding block -
	// the original executed Action (action_ref + parameter_hash) plus the
	// declared PostconditionSpec/VerificationNeed pair and its data-class
	// expectation (VerificationNeed vocabulary; no parallel names) - and an
	// allowed verification-purpose read emits the signed ObservationReceipt
	// on the response. The block is all-or-nothing (every member required);
	// observation authority, source version, observed-at and freshness stay
	// SERVER-DERIVED: no request property may carry them.
	t.Run("VerificationReadBindsDeclaredNeedAndEmitsReceipt", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")

		// Proto mirror (append-only): the evidence plane carries the same
		// request-side binding block. The read-response envelope remains an
		// OpenAPI/SDK surface (as since contract v1.2.0), so no response
		// message is mirrored.
		raw, err := os.ReadFile(protoPath(filepath.Join("evidence", "v1", "evidence.proto")))
		if err != nil {
			t.Fatalf("evidence.proto missing: %v", err)
		}
		for _, token := range []string{
			"message VerificationBinding",
			"string action_ref = 1;",
			"string parameter_hash = 2;",
			"string postcondition_id = 3;",
			"string verification_need_id = 4;",
			"string data_class = 5;",
			"VerificationBinding verification_binding = 9;",
		} {
			if !strings.Contains(string(raw), token) {
				t.Errorf("evidence.proto is missing frozen declaration %q", token)
			}
		}

		readRequest, ok := schemas["EvidenceReadRequest"].(map[string]any)
		if !ok {
			t.Fatal("EvidenceReadRequest schema missing")
		}
		requestProperties, requestRequired := composedSchema(t, runtimeDoc, readRequest)
		if bindingProperty, ok := requestProperties["verification_binding"].(map[string]any); !ok {
			t.Error("EvidenceReadRequest must declare the optional verification_binding block")
		} else {
			if bindingProperty["$ref"] != "#/components/schemas/VerificationBinding" {
				t.Errorf("verification_binding = %v, want $ref VerificationBinding", bindingProperty["$ref"])
			}
			if requestRequired["verification_binding"] {
				t.Error("verification_binding is OPTIONAL on EvidenceReadRequest (required only with the verification purpose; the SDK rules are normative)")
			}
		}
		for _, serverDerived := range []string{"authority", "observed_at", "fresh_until", "source_version"} {
			if _, exists := requestProperties[serverDerived]; exists {
				t.Errorf("EvidenceReadRequest must not accept server-derived observation metadata %q from the caller", serverDerived)
			}
		}

		readResponse, ok := schemas["EvidenceReadResponse"].(map[string]any)
		if !ok {
			t.Fatal("EvidenceReadResponse schema missing")
		}
		responseProperties, responseRequired := composedSchema(t, runtimeDoc, readResponse)
		if receiptProperty, ok := responseProperties["observation_receipt"].(map[string]any); !ok {
			t.Error("EvidenceReadResponse must declare the optional observation_receipt emission")
		} else {
			receiptAllOf, _ := receiptProperty["allOf"].([]any)
			receiptRef := ""
			if len(receiptAllOf) == 1 {
				if entry, ok := receiptAllOf[0].(map[string]any); ok {
					receiptRef, _ = entry["$ref"].(string)
				}
			}
			if receiptRef != "#/components/schemas/ObservationReceipt" {
				t.Errorf("observation_receipt must reference the frozen ObservationReceipt schema, got %v", receiptProperty)
			}
			if responseRequired["observation_receipt"] {
				t.Error("observation_receipt is emitted ONLY on allowed verification-purpose reads and must stay optional")
			}
		}

		schema, ok := schemas["VerificationBinding"].(map[string]any)
		if !ok {
			t.Fatal("VerificationBinding schema missing from gateway-runtime.yaml")
		}
		frozen := []string{"action_ref", "parameter_hash", "postcondition_id", "verification_need_id", "data_class"}
		properties, required := composedSchema(t, runtimeDoc, schema)
		var gotProperties []string
		for name := range properties {
			gotProperties = append(gotProperties, name)
		}
		sort.Strings(gotProperties)
		wantFrozen := append([]string(nil), frozen...)
		sort.Strings(wantFrozen)
		if !equalStrings(gotProperties, wantFrozen) {
			t.Errorf("VerificationBinding properties = %v, want frozen set %v", gotProperties, wantFrozen)
		}
		if gotRequired := sortedNames(required); !equalStrings(gotRequired, wantFrozen) {
			t.Errorf("VerificationBinding required = %v, want the all-or-nothing block %v", gotRequired, wantFrozen)
		}
		actionRef := requireProperty(t, runtimeDoc, properties, "action_ref")
		if pattern, _ := actionRef["pattern"].(string); !strings.HasPrefix(pattern, "^act_") {
			t.Errorf("VerificationBinding action_ref pattern = %q, want an opaque act_ handle", pattern)
		}
		parameterHash := requireProperty(t, runtimeDoc, properties, "parameter_hash")
		if parameterHash["pattern"] != sha256RefPattern {
			t.Errorf("VerificationBinding parameter_hash pattern = %v, want %q", parameterHash["pattern"], sha256RefPattern)
		}
		for _, serverDerived := range []string{"authority", "observed_at", "fresh_until", "source_version", "source"} {
			if _, exists := properties[serverDerived]; exists {
				t.Errorf("VerificationBinding must not accept server-derived observation metadata %q from the caller", serverDerived)
			}
		}
	})

	t.Run("NoVendorSpecificNames", func(t *testing.T) {
		for name, text := range texts {
			lower := strings.ToLower(text)
			for _, vendor := range []string{"agentatlas", "agent_atlas", "agent-atlas"} {
				if strings.Contains(lower, vendor) {
					t.Errorf("%s still contains vendor-specific name %q; the generic public contract must be vendor neutral", name, vendor)
				}
			}
		}
		if _, exists := nestedMap(t, runtimeDoc, "components", "schemas")["AgentAtlasPermission"]; exists {
			t.Error("AgentAtlasPermission must not exist; permissions are neutral PrincipalPermission values")
		}
	})

	t.Run("RequestEnvelopeCarriesOnlyCorrelation", func(t *testing.T) {
		for name, doc := range documents {
			envelope, ok := nestedMap(t, doc, "components", "schemas")["RequestEnvelope"].(map[string]any)
			if !ok {
				t.Errorf("%s: RequestEnvelope schema missing", name)
				continue
			}
			properties, required := composedSchema(t, doc, envelope)
			if got := sortedNames(required); !equalStrings(got, []string{"request_id"}) {
				t.Errorf("%s RequestEnvelope required = %v, want [request_id]", name, got)
			}
			var names []string
			for property := range properties {
				names = append(names, property)
			}
			sort.Strings(names)
			if !equalStrings(names, []string{"request_id", "trace_id"}) {
				t.Errorf("%s RequestEnvelope properties = %v, want [request_id trace_id]", name, names)
			}
		}
	})

	t.Run("ActionRequestIsTypedAndFullyBound", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")
		schema, ok := schemas["ActionRequest"].(map[string]any)
		if !ok {
			t.Fatal("ActionRequest schema missing from gateway-runtime.yaml")
		}
		properties, required := composedSchema(t, runtimeDoc, schema)
		for _, want := range []string{
			"request_id", "business_context_ref", "capability", "parameters",
			"parameter_hash", "purpose", "risk_decision", "idempotency_key",
			"expires_at", "expected_receipt_schema",
		} {
			if !required[want] {
				t.Errorf("ActionRequest must require %q, required = %v", want, sortedNames(required))
			}
		}
		for _, want := range []string{"trace_id", "constraints", "approval_plan_ref", "preconditions", "postconditions", "verification_needs", "compensation_ref"} {
			if _, ok := properties[want]; !ok {
				t.Errorf("ActionRequest must declare property %q", want)
			}
		}
		for propertyName, wantItemsRef := range map[string]string{
			"postconditions":     "#/components/schemas/PostconditionSpec",
			"verification_needs": "#/components/schemas/VerificationNeed",
		} {
			array := requireProperty(t, runtimeDoc, properties, propertyName)
			items, _ := array["items"].(map[string]any)
			if items["$ref"] != wantItemsRef {
				t.Errorf("ActionRequest %s items = %v, want %q", propertyName, items["$ref"], wantItemsRef)
			}
		}
		for _, legacy := range []string{"action", "input", "resource"} {
			if _, ok := properties[legacy]; ok {
				t.Errorf("ActionRequest must not carry legacy untyped field %q", legacy)
			}
		}
		hash := requireProperty(t, runtimeDoc, properties, "parameter_hash")
		if hash["pattern"] != sha256RefPattern {
			t.Errorf("parameter_hash pattern = %v, want %q", hash["pattern"], sha256RefPattern)
		}
		capability := requireProperty(t, runtimeDoc, properties, "capability")
		pattern, _ := capability["pattern"].(string)
		if !strings.Contains(pattern, `\.`) {
			t.Errorf("capability pattern %q must require a namespaced business-semantic capability", pattern)
		}
		idempotency := requireProperty(t, runtimeDoc, properties, "idempotency_key")
		if minLength, _ := idempotency["minLength"].(int); minLength < 16 {
			t.Errorf("idempotency_key minLength = %v, want >= 16", idempotency["minLength"])
		}
		expiry := requireProperty(t, runtimeDoc, properties, "expires_at")
		if expiry["format"] != "date-time" {
			t.Errorf("expires_at format = %v, want date-time", expiry["format"])
		}
	})

	t.Run("NoUntypedActionInputPair", func(t *testing.T) {
		for name, doc := range documents {
			walkYAML(t, doc, "", func(path string, node any) {
				object, ok := node.(map[string]any)
				if !ok {
					return
				}
				properties, ok := object["properties"].(map[string]any)
				if !ok {
					return
				}
				if _, hasAction := properties["action"]; !hasAction {
					return
				}
				if _, hasInput := properties["input"]; hasInput {
					t.Errorf("%s%s pairs untyped `action` with `input`; actions are typed capability + parameters + parameter_hash", name, path)
				}
			})
		}
	})

	t.Run("RiskDecisionIsSignedAndOperationBound", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")
		schema, ok := schemas["RiskDecision"].(map[string]any)
		if !ok {
			t.Fatal("RiskDecision schema missing from gateway-runtime.yaml")
		}
		properties, required := composedSchema(t, runtimeDoc, schema)
		for _, want := range []string{
			"decision_id", "authority", "risk_level", "capability",
			"parameter_hash", "business_context_ref", "issued_at", "expires_at", "signature",
		} {
			if !required[want] {
				t.Errorf("RiskDecision must require %q (an unsigned or unbound risk decision is rejected), required = %v", want, sortedNames(required))
			}
		}
		signature := requireProperty(t, runtimeDoc, properties, "signature")
		_, signatureRequired := composedSchema(t, runtimeDoc, signature)
		for _, want := range []string{"algorithm", "key_id", "value"} {
			if !signatureRequired[want] {
				t.Errorf("Signature must require %q, required = %v", want, sortedNames(signatureRequired))
			}
		}
	})

	t.Run("StepGrantBindsOneExactOperation", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")
		expectations := map[string][]string{
			"StepGrantRequest":        {"request_id", "business_context_ref", "capability", "parameter_hash", "purpose", "ttl_seconds"},
			"StepGrantResponse":       {"grant_ref", "business_context_ref", "capability", "parameter_hash", "one_use", "expires_at"},
			"StepGrantVerifyRequest":  {"grant_ref", "capability", "parameter_hash"},
			"StepGrantVerifyResponse": {"valid", "grant_ref", "capability", "parameter_hash", "one_use", "expires_at"},
		}
		for schemaName, wantRequired := range expectations {
			schema, ok := schemas[schemaName].(map[string]any)
			if !ok {
				t.Errorf("%s schema missing", schemaName)
				continue
			}
			properties, required := composedSchema(t, runtimeDoc, schema)
			for _, want := range wantRequired {
				if !required[want] {
					t.Errorf("%s must require %q, required = %v", schemaName, want, sortedNames(required))
				}
			}
			for _, legacy := range []string{"resource_type", "resource_id", "action", "scope", "scopes", "token"} {
				if _, ok := properties[legacy]; ok {
					t.Errorf("%s must not use legacy selector %q; grants bind capability + parameter_hash exactly", schemaName, legacy)
				}
			}
			if _, ok := properties["one_use"]; ok {
				oneUse := requireProperty(t, runtimeDoc, properties, "one_use")
				enum, _ := oneUse["enum"].([]any)
				if len(enum) != 1 || enum[0] != true {
					t.Errorf("%s one_use enum = %v, want [true] (one-use semantics are part of the type contract)", schemaName, oneUse["enum"])
				}
			}
		}
	})

	t.Run("ActionStatusStatesAreFrozen", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")
		schema, ok := schemas["ActionStatus"].(map[string]any)
		if !ok {
			t.Fatal("ActionStatus schema missing from gateway-runtime.yaml")
		}
		enum, _ := schema["enum"].([]any)
		var got []string
		for _, value := range enum {
			name, _ := value.(string)
			got = append(got, name)
		}
		if !equalStrings(got, frozenActionStates) {
			t.Errorf("ActionStatus enum = %v, want frozen states %v", got, frozenActionStates)
		}
	})

	t.Run("EvidenceIsLocatedThroughOpaqueHandles", func(t *testing.T) {
		schemas := nestedMap(t, runtimeDoc, "components", "schemas")
		for _, gone := range []string{"ResourceRef", "LocatedResource"} {
			if _, ok := schemas[gone]; ok {
				t.Errorf("%s must not exist; evidence is addressed by opaque EvidenceHandle, never connector resource selectors", gone)
			}
		}
		schema, ok := schemas["EvidenceHandle"].(map[string]any)
		if !ok {
			t.Fatal("EvidenceHandle schema missing")
		}
		properties, required := composedSchema(t, runtimeDoc, schema)
		for _, want := range []string{"evidence_ref", "data_class"} {
			if !required[want] {
				t.Errorf("EvidenceHandle must require %q", want)
			}
		}
		ref := requireProperty(t, runtimeDoc, properties, "evidence_ref")
		pattern, _ := ref["pattern"].(string)
		if !strings.HasPrefix(pattern, "^evd_") {
			t.Errorf("evidence_ref pattern = %q, want an opaque evd_ handle", pattern)
		}
		request, ok := schemas["EvidenceRequest"].(map[string]any)
		if !ok {
			t.Fatal("EvidenceRequest schema missing")
		}
		requestProperties, requestRequired := composedSchema(t, runtimeDoc, request)
		for _, want := range []string{"data_needs", "purpose", "expires_at"} {
			if !requestRequired[want] {
				t.Errorf("EvidenceRequest must require %q", want)
			}
		}
		if _, ok := requestProperties["business_context_ref"]; !ok {
			t.Error("EvidenceRequest must declare business_context_ref")
		}
	})

	t.Run("OpenAPIRefsResolve", func(t *testing.T) {
		for name, doc := range documents {
			walkYAML(t, doc, "", func(path string, node any) {
				object, ok := node.(map[string]any)
				if !ok {
					return
				}
				ref, ok := object["$ref"].(string)
				if !ok {
					return
				}
				if !strings.HasPrefix(ref, "#/") {
					t.Errorf("%s%s: external $ref %q", name, path, ref)
					return
				}
				current := any(doc)
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					asMap, ok := current.(map[string]any)
					if !ok {
						t.Errorf("%s%s: $ref %q does not resolve", name, path, ref)
						return
					}
					current, ok = asMap[part]
					if !ok {
						t.Errorf("%s%s: $ref %q does not resolve (missing %q)", name, path, ref, part)
						return
					}
				}
			})
		}
	})

	t.Run("PublicProtosAreNeutralAndComplete", func(t *testing.T) {
		fieldRe := regexp.MustCompile(`(?m)^\s*(?:repeated\s+|optional\s+)?[A-Za-z0-9_.]+\s+([a-z0-9_]+)\s*=\s*\d+;`)
		for _, rel := range publicProtoFiles {
			raw, err := os.ReadFile(protoPath(rel))
			if err != nil {
				t.Errorf("public proto %s is missing: %v", rel, err)
				continue
			}
			text := string(raw)
			lower := strings.ToLower(text)
			for _, vendor := range []string{"agentatlas", "agent_atlas", "agent-atlas"} {
				if strings.Contains(lower, vendor) {
					t.Errorf("%s contains vendor-specific name %q", rel, vendor)
				}
			}
			for _, match := range fieldRe.FindAllStringSubmatch(text, -1) {
				if reason := forbiddenPublicFieldName(match[1]); reason != "" {
					t.Errorf("%s declares forbidden field %q (%s)", rel, match[1], reason)
				}
			}
		}

		requiredTokens := map[string][]string{
			filepath.Join("evidence", "v1", "evidence.proto"): {
				"package agentnexus.evidence.v1;",
				"message DataNeed", "string data_class", "message EvidenceRequest",
				"message EvidenceHandle", "string evidence_ref", "string business_context_ref",
			},
			filepath.Join("actions", "v1", "actions.proto"): {
				"package agentnexus.actions.v1;",
				"message BusinessCapabilityRequest", "message ActionRequest", "message Action ",
				"message ActionReceipt", "string parameter_hash", "string idempotency_key",
				"string expected_receipt_schema", "string compensation_ref",
				"agentnexus.trust.v1.RiskDecision risk_decision",
				"agentnexus.trust.v1.ApprovalPlanRef approval_plan_ref",
				// GA Task 0A amendment (plan dc81e80): declared postconditions,
				// verification needs and the signed bounded-observation receipt.
				"message PostconditionSpec", "message VerificationNeed",
				"message ObservationReceipt",
				"repeated PostconditionSpec postconditions",
				"repeated VerificationNeed verification_needs",
				"string observation_ref", "string postcondition_id",
				"string verification_need_id", "int64 source_version",
				"string observed_at", "string fresh_until",
				"string observation_hash", "string audit_ref_id",
			},
			filepath.Join("trust", "v1", "trust.proto"): {
				"package agentnexus.trust.v1;",
				"TRUST_CLASS_FIRST_PARTY_TRUSTED = 1;",
				"TRUST_CLASS_CERTIFIED_THIRD_PARTY = 2;",
				"TRUST_CLASS_UNTRUSTED = 3;",
				"APPROVAL_DECISION_UNSPECIFIED = 0;",
				"APPROVAL_DECISION_APPROVED = 1;",
				"APPROVAL_DECISION_DENIED = 2;",
				"APPROVAL_DECISION_NARROWED = 3;",
				"message PrincipalContext", "message Signature", "message RiskDecision",
				"Signature signature", "message ApprovalPlanRef", "message ApprovalRequest",
				"message ApprovalEvidence", "ApprovalDecision decision", "Signature attestation",
				"message StepGrant", "bool one_use",
			},
			filepath.Join("audit", "v1", "audit.proto"): {
				"package agentnexus.audit.v1;",
				"string tenant_ref", "uint64 tenant_seq", "string business_context_ref",
				"string principal_ref", "string agent_client_ref", "string agent_release_ref",
				"string org_snapshot_ref", "string capability", "string parameter_hash",
				"string risk_decision_ref", "string approval_evidence_ref", "string grant_ref",
				"string action_ref", "status_from", "status_to", "string receipt_ref",
				"string prev_hash", "string event_hash",
			},
		}
		for rel, tokens := range requiredTokens {
			raw, err := os.ReadFile(protoPath(rel))
			if err != nil {
				continue // already reported above
			}
			text := string(raw)
			for _, token := range tokens {
				if !strings.Contains(text, token) {
					t.Errorf("%s is missing frozen declaration %q", rel, token)
				}
			}
		}

		actionStates := []string{
			"ACTION_STATUS_UNSPECIFIED = 0;", "ACTION_STATUS_REQUESTED = 1;",
			"ACTION_STATUS_AWAITING_APPROVAL = 2;", "ACTION_STATUS_GRANTED = 3;",
			"ACTION_STATUS_DISPATCHED = 4;", "ACTION_STATUS_EXECUTING = 5;",
			"ACTION_STATUS_SUCCEEDED = 6;", "ACTION_STATUS_FAILED = 7;",
			"ACTION_STATUS_RESULT_UNKNOWN = 8;", "ACTION_STATUS_RECONCILING = 9;",
			"ACTION_STATUS_COMPENSATING = 10;", "ACTION_STATUS_HUMAN_TAKEOVER = 11;",
		}
		raw, err := os.ReadFile(protoPath(filepath.Join("actions", "v1", "actions.proto")))
		if err == nil {
			for _, state := range actionStates {
				if !strings.Contains(string(raw), state) {
					t.Errorf("actions.proto is missing frozen state %q", state)
				}
			}
		}
	})

	t.Run("ConnectorTopologyStaysConnectorInternal", func(t *testing.T) {
		raw, err := os.ReadFile(protoPath(filepath.Join("connectors", "v1", "connectors.proto")))
		if err != nil {
			t.Fatalf("connector-internal proto missing: %v", err)
		}
		if !strings.Contains(string(raw), "connector_instance_id") {
			t.Error("connector topology must keep living in connector-internal messages (connectors/v1); it may never migrate into Agent messages")
		}
	})
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
