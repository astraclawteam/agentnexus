package runtime

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The TestContract* suite freezes the vendor-neutral Agent runtime contract
// (ELC-NEXUS-1 candidate). Every rejection listed by GA Task 0A Step 1 is
// proven here:
//
//   - trusted identity (enterprise_id, actor_user_id, connector_instance_id)
//     never decodes from public request JSON;
//   - no AgentAtlas-specific generic type exists in this package;
//   - no connector-specific resource selector exists in this package;
//   - the legacy untyped `action` + `input` shape is rejected;
//   - an unsigned RiskDecision is rejected;
//   - a missing/mismatching parameter hash is rejected;
//   - a missing idempotency key is rejected;
//   - a Step Grant not bound to one exact operation is rejected.

var contractNow = time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)

func validSignature() Signature {
	return Signature{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     "risk-authority-signing-1",
		Value:     "c2lnbmF0dXJlLWJ5dGVz",
	}
}

func validRiskDecision(capability, parameterHash, businessContextRef string) RiskDecision {
	return RiskDecision{
		DecisionID:         "rsk_0123456789abcdef",
		Authority:          "risk-authority.example",
		RiskLevel:          RiskHigh,
		Reasons:            []string{"external_side_effect"},
		Capability:         capability,
		ParameterHash:      parameterHash,
		BusinessContextRef: businessContextRef,
		IssuedAt:           contractNow,
		ExpiresAt:          contractNow.Add(time.Hour),
		Signature:          validSignature(),
	}
}

func validActionRequest() ActionRequest {
	parameters := json.RawMessage(`{"po_number":"PO-1009","amount":125000.5}`)
	parameterHash := HashParameters(parameters)
	return ActionRequest{
		RequestID:          "req-01HZX4Y7Q9",
		TraceID:            "trace-7f00",
		BusinessContextRef: "wc_0123456789abcdef",
		Capability:         "erp.purchase_order.approve",
		Parameters:         parameters,
		ParameterHash:      parameterHash,
		Purpose:            "approve purchase order PO-1009",
		RiskDecision:       validRiskDecision("erp.purchase_order.approve", parameterHash, "wc_0123456789abcdef"),
		ApprovalPlanRef: &ApprovalPlanRef{
			PlanRef:   "apl_0123456789abcdef",
			PlanHash:  HashParameters([]byte(`{"steps":["upward_review"]}`)),
			Authority: "approval-authority.example",
		},
		IdempotencyKey:        "idem-0123456789abcdef",
		Preconditions:         []Precondition{{Kind: "state_hash", Reference: "po:PO-1009", Expected: HashParameters([]byte("state"))}},
		ExpiresAt:             contractNow.Add(30 * time.Minute),
		ExpectedReceiptSchema: "receipt.erp.purchase_order.approve.v1",
		CompensationRef:       "erp.purchase_order.reject",
	}
}

func validStepGrant() StepGrant {
	return StepGrant{
		GrantRef:           "grant_0123456789abcdef",
		BusinessContextRef: "wc_0123456789abcdef",
		Capability:         "erp.purchase_order.approve",
		ParameterHash:      HashParameters([]byte(`{"po_number":"PO-1009"}`)),
		OneUse:             true,
		IssuedAt:           contractNow,
		ExpiresAt:          contractNow.Add(5 * time.Minute),
	}
}

func mustContainError(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error containing %q, got nil", fragment)
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("want error containing %q, got %q", fragment, err.Error())
	}
}

func TestContractActionRequestCanonicalValidation(t *testing.T) {
	if err := validActionRequest().Validate(); err != nil {
		t.Fatalf("canonical action request must validate, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*ActionRequest)
		wantErr string
	}{
		{"missing request id", func(r *ActionRequest) { r.RequestID = "" }, "request_id"},
		{"oversized request id", func(r *ActionRequest) { r.RequestID = strings.Repeat("x", 129) }, "request_id"},
		{"missing business context", func(r *ActionRequest) { r.BusinessContextRef = "" }, "business_context_ref"},
		{"non-opaque business context", func(r *ActionRequest) { r.BusinessContextRef = "case-123" }, "business_context_ref"},
		{"missing capability", func(r *ActionRequest) { r.Capability = "" }, "capability"},
		{"non-semantic capability", func(r *ActionRequest) { r.Capability = "update" }, "capability"},
		{"free-text capability", func(r *ActionRequest) { r.Capability = "Create PO" }, "capability"},
		{"nil parameters", func(r *ActionRequest) { r.Parameters = nil }, "parameters"},
		{"missing parameter hash", func(r *ActionRequest) { r.ParameterHash = "" }, "parameter_hash"},
		{"malformed parameter hash", func(r *ActionRequest) { r.ParameterHash = "sha256:nothex" }, "parameter_hash"},
		{"parameter hash not bound to parameters", func(r *ActionRequest) {
			r.ParameterHash = HashParameters([]byte(`{"po_number":"PO-9999"}`))
			r.RiskDecision.ParameterHash = r.ParameterHash
		}, "parameter_hash does not match"},
		{"missing purpose", func(r *ActionRequest) { r.Purpose = "" }, "purpose"},
		{"unsigned risk decision", func(r *ActionRequest) { r.RiskDecision.Signature = Signature{} }, "signature"},
		{"risk decision missing key id", func(r *ActionRequest) { r.RiskDecision.Signature.KeyID = "" }, "key_id"},
		{"risk decision capability mismatch", func(r *ActionRequest) { r.RiskDecision.Capability = "erp.purchase_order.reject" }, "risk_decision"},
		{"risk decision parameter hash mismatch", func(r *ActionRequest) {
			r.RiskDecision.ParameterHash = HashParameters([]byte("other"))
		}, "risk_decision"},
		{"risk decision context mismatch", func(r *ActionRequest) { r.RiskDecision.BusinessContextRef = "wc_ffffffffffffffff" }, "risk_decision"},
		{"missing idempotency key", func(r *ActionRequest) { r.IdempotencyKey = "" }, "idempotency_key"},
		{"short idempotency key", func(r *ActionRequest) { r.IdempotencyKey = "short" }, "idempotency_key"},
		{"missing expiry", func(r *ActionRequest) { r.ExpiresAt = time.Time{} }, "expires_at"},
		{"missing expected receipt schema", func(r *ActionRequest) { r.ExpectedReceiptSchema = "" }, "expected_receipt_schema"},
		{"approval plan authored by agentnexus", func(r *ActionRequest) { r.ApprovalPlanRef.Authority = "AgentNexus" }, "never authors"},
		{"approval plan malformed hash", func(r *ActionRequest) { r.ApprovalPlanRef.PlanHash = "md5:abc" }, "plan_hash"},
		{"approval plan non-opaque ref", func(r *ActionRequest) { r.ApprovalPlanRef.PlanRef = "plan-1" }, "plan_ref"},
		{"precondition missing reference", func(r *ActionRequest) { r.Preconditions = []Precondition{{Kind: "state_hash"}} }, "precondition"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := validActionRequest()
			tc.mutate(&request)
			mustContainError(t, request.Validate(), tc.wantErr)
		})
	}
}

func TestContractRejectsTrustedIdentityInRequestJSON(t *testing.T) {
	base, err := json.Marshal(validActionRequest())
	if err != nil {
		t.Fatal(err)
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

	t.Run("clean request decodes", func(t *testing.T) {
		if _, err := DecodeActionRequest(base); err != nil {
			t.Fatalf("canonical request JSON must decode, got %v", err)
		}
	})

	forbidden := []string{"enterprise_id", "actor_user_id", "connector_instance_id"}
	for _, key := range forbidden {
		t.Run("top level "+key, func(t *testing.T) {
			raw := inject(t, func(doc map[string]any) { doc[key] = "supplied-by-caller" })
			_, err := DecodeActionRequest(raw)
			mustContainError(t, err, key)
			if !errors.Is(err, ErrTrustedIdentityInRequest) {
				t.Fatalf("want ErrTrustedIdentityInRequest, got %v", err)
			}
		})
	}

	t.Run("nested actor_user_id inside risk_decision", func(t *testing.T) {
		raw := inject(t, func(doc map[string]any) {
			doc["risk_decision"].(map[string]any)["actor_user_id"] = "user-7"
		})
		_, err := DecodeActionRequest(raw)
		mustContainError(t, err, "actor_user_id")
	})

	t.Run("enterprise-prefixed alias rejected", func(t *testing.T) {
		raw := inject(t, func(doc map[string]any) { doc["enterprise_user_id"] = "user-7" })
		_, err := DecodeActionRequest(raw)
		mustContainError(t, err, "enterprise_user_id")
	})

	t.Run("connector selector alias rejected", func(t *testing.T) {
		raw := inject(t, func(doc map[string]any) { doc["connector_resource"] = "mes.workorders" })
		_, err := DecodeActionRequest(raw)
		mustContainError(t, err, "connector_resource")
	})

	t.Run("business data inside hashed parameters stays opaque", func(t *testing.T) {
		// A business record column legitimately named enterprise_id is DATA,
		// not trust: it lives inside the hash-bound parameters payload and
		// must not be confused with the trusted envelope.
		parameters := json.RawMessage(`{"enterprise_id":"erp-column-value"}`)
		request := validActionRequest()
		request.Parameters = parameters
		request.ParameterHash = HashParameters(parameters)
		request.RiskDecision.ParameterHash = request.ParameterHash
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeActionRequest(raw); err != nil {
			t.Fatalf("hash-bound parameters must stay opaque, got %v", err)
		}
	})

	t.Run("unknown envelope fields rejected", func(t *testing.T) {
		raw := inject(t, func(doc map[string]any) { doc["org_version"] = 7 })
		if _, err := DecodeActionRequest(raw); err == nil {
			t.Fatal("caller-supplied org_version must not decode")
		}
	})
}

func TestContractRejectsLegacyUntypedActionShape(t *testing.T) {
	raw := []byte(`{
		"request_id": "req-1",
		"business_context_ref": "wc_0123456789abcdef",
		"action": "crm.export",
		"input": {"all": true}
	}`)
	_, err := DecodeActionRequest(raw)
	if err == nil {
		t.Fatal("legacy action+input shape must be rejected")
	}
	if !errors.Is(err, ErrLegacyActionShape) {
		t.Fatalf("want ErrLegacyActionShape, got %v", err)
	}
}

func TestContractRiskDecisionMustBeSigned(t *testing.T) {
	valid := validRiskDecision("erp.purchase_order.approve", HashParameters([]byte("p")), "wc_0123456789abcdef")
	if err := valid.Validate(); err != nil {
		t.Fatalf("signed risk decision must validate, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*RiskDecision)
		wantErr string
	}{
		{"zero signature", func(d *RiskDecision) { d.Signature = Signature{} }, "signature"},
		{"missing algorithm", func(d *RiskDecision) { d.Signature.Algorithm = "" }, "algorithm"},
		{"unknown algorithm", func(d *RiskDecision) { d.Signature.Algorithm = "rot13" }, "algorithm"},
		{"missing key id", func(d *RiskDecision) { d.Signature.KeyID = "" }, "key_id"},
		{"missing value", func(d *RiskDecision) { d.Signature.Value = "" }, "value"},
		{"missing authority", func(d *RiskDecision) { d.Authority = "" }, "authority"},
		{"missing decision id", func(d *RiskDecision) { d.DecisionID = "" }, "decision_id"},
		{"missing risk level", func(d *RiskDecision) { d.RiskLevel = "" }, "risk_level"},
		{"unknown risk level", func(d *RiskDecision) { d.RiskLevel = "extreme" }, "risk_level"},
		{"missing capability binding", func(d *RiskDecision) { d.Capability = "" }, "capability"},
		{"missing parameter hash binding", func(d *RiskDecision) { d.ParameterHash = "" }, "parameter_hash"},
		{"missing business context binding", func(d *RiskDecision) { d.BusinessContextRef = "" }, "business_context_ref"},
		{"missing issued at", func(d *RiskDecision) { d.IssuedAt = time.Time{} }, "issued_at"},
		{"missing expiry", func(d *RiskDecision) { d.ExpiresAt = time.Time{} }, "expires_at"},
		{"expiry not after issue", func(d *RiskDecision) { d.ExpiresAt = d.IssuedAt }, "expires_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := validRiskDecision("erp.purchase_order.approve", HashParameters([]byte("p")), "wc_0123456789abcdef")
			tc.mutate(&decision)
			mustContainError(t, decision.Validate(), tc.wantErr)
		})
	}
}

func TestContractStepGrantBindsOneExactOperation(t *testing.T) {
	if err := validStepGrant().Validate(); err != nil {
		t.Fatalf("exactly bound step grant must validate, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*StepGrant)
		wantErr string
	}{
		{"missing grant ref", func(g *StepGrant) { g.GrantRef = "" }, "grant_ref"},
		{"non-opaque grant ref", func(g *StepGrant) { g.GrantRef = "token-1" }, "grant_ref"},
		{"missing business context", func(g *StepGrant) { g.BusinessContextRef = "" }, "business_context_ref"},
		{"missing capability binding", func(g *StepGrant) { g.Capability = "" }, "capability"},
		{"non-semantic capability", func(g *StepGrant) { g.Capability = "read" }, "capability"},
		{"missing parameter hash binding", func(g *StepGrant) { g.ParameterHash = "" }, "parameter_hash"},
		{"malformed parameter hash", func(g *StepGrant) { g.ParameterHash = "deadbeef" }, "parameter_hash"},
		{"reusable grant", func(g *StepGrant) { g.OneUse = false }, "one-use"},
		{"missing issue time", func(g *StepGrant) { g.IssuedAt = time.Time{} }, "issued_at"},
		{"missing expiry", func(g *StepGrant) { g.ExpiresAt = time.Time{} }, "expires_at"},
		{"expiry not after issue", func(g *StepGrant) { g.ExpiresAt = g.IssuedAt.Add(-time.Second) }, "expires_at"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grant := validStepGrant()
			tc.mutate(&grant)
			mustContainError(t, grant.Validate(), tc.wantErr)
		})
	}
}

func TestContractEvidenceRequestAndHandles(t *testing.T) {
	need := DataNeed{NeedID: "need-1", DataClass: "hr.employee_directory", Purpose: "resolve approver chain"}
	request := EvidenceRequest{
		RequestID:          "req-2",
		TraceID:            "trace-2",
		BusinessContextRef: "wc_0123456789abcdef",
		DataNeeds:          []DataNeed{need},
		Purpose:            "locate evidence for PO approval",
		ExpiresAt:          contractNow.Add(10 * time.Minute),
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("canonical evidence request must validate, got %v", err)
	}

	t.Run("requires at least one data need", func(t *testing.T) {
		r := request
		r.DataNeeds = nil
		mustContainError(t, r.Validate(), "data_needs")
	})
	t.Run("data need requires data class", func(t *testing.T) {
		r := request
		r.DataNeeds = []DataNeed{{NeedID: "need-1", Purpose: "p"}}
		mustContainError(t, r.Validate(), "data_class")
	})
	t.Run("data need requires purpose", func(t *testing.T) {
		r := request
		r.DataNeeds = []DataNeed{{NeedID: "need-1", DataClass: "hr.employee_directory"}}
		mustContainError(t, r.Validate(), "purpose")
	})
	t.Run("requires expiry", func(t *testing.T) {
		r := request
		r.ExpiresAt = time.Time{}
		mustContainError(t, r.Validate(), "expires_at")
	})
	t.Run("rejects trusted identity in JSON", func(t *testing.T) {
		raw := []byte(`{"request_id":"req-2","enterprise_id":"ent-1","data_needs":[],"purpose":"p"}`)
		_, err := DecodeEvidenceRequest(raw)
		mustContainError(t, err, "enterprise_id")
	})
	t.Run("evidence handle is an opaque typed handle", func(t *testing.T) {
		handle := EvidenceHandle{EvidenceRef: "evd_0123456789abcdef", DataClass: "hr.employee_directory"}
		if err := handle.Validate(); err != nil {
			t.Fatalf("opaque evidence handle must validate, got %v", err)
		}
		handle.EvidenceRef = "postgres://mes/workorders/17"
		mustContainError(t, handle.Validate(), "evidence_ref")
	})
}

func TestContractBusinessCapabilityRequest(t *testing.T) {
	request := BusinessCapabilityRequest{
		RequestID:          "req-3",
		BusinessContextRef: "wc_0123456789abcdef",
		Capability:         "erp.purchase_order.approve",
		Purpose:            "check eligibility before drafting the action",
		ExpiresAt:          contractNow.Add(10 * time.Minute),
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("canonical capability request must validate, got %v", err)
	}
	t.Run("requires semantic capability", func(t *testing.T) {
		r := request
		r.Capability = "SELECT * FROM workorders"
		mustContainError(t, r.Validate(), "capability")
	})
	t.Run("optional parameter hash must be well formed", func(t *testing.T) {
		r := request
		r.ParameterHash = "sha256:short"
		mustContainError(t, r.Validate(), "parameter_hash")
	})
	t.Run("rejects trusted identity in JSON", func(t *testing.T) {
		raw := []byte(`{"request_id":"req-3","capability":"erp.purchase_order.approve","purpose":"p","connector_instance_id":"conn-9"}`)
		_, err := DecodeBusinessCapabilityRequest(raw)
		mustContainError(t, err, "connector_instance_id")
	})
}

func TestContractApprovalTypes(t *testing.T) {
	plan := ApprovalPlanRef{
		PlanRef:   "apl_0123456789abcdef",
		PlanHash:  HashParameters([]byte("plan")),
		Authority: "approval-authority.example",
	}
	request := ApprovalRequest{
		RequestID:          "req-4",
		BusinessContextRef: "wc_0123456789abcdef",
		Capability:         "erp.purchase_order.approve",
		ParameterHash:      HashParameters([]byte("p")),
		Purpose:            "route the governed change",
		Plan:               plan,
		ExpiresAt:          contractNow.Add(time.Hour),
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("canonical approval request must validate, got %v", err)
	}

	t.Run("agentnexus never authors approval plans", func(t *testing.T) {
		r := request
		r.Plan.Authority = "agentnexus"
		mustContainError(t, r.Validate(), "never authors")
	})
	t.Run("plan requires digest binding", func(t *testing.T) {
		r := request
		r.Plan.PlanHash = ""
		mustContainError(t, r.Validate(), "plan_hash")
	})

	evidence := ApprovalEvidence{
		ApprovalRef:       "apv_0123456789abcdef",
		PlanRef:           plan.PlanRef,
		PlanHash:          plan.PlanHash,
		Capability:        "erp.purchase_order.approve",
		ParameterHash:     HashParameters([]byte("p")),
		Decision:          ApprovalApproved,
		ApproverAuthority: "approval-authority.example",
		DecidedAt:         contractNow,
		Attestation:       validSignature(),
	}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("attested approval evidence must validate, got %v", err)
	}
	t.Run("approval evidence must be attested", func(t *testing.T) {
		e := evidence
		e.Attestation = Signature{}
		mustContainError(t, e.Validate(), "attestation")
	})
	t.Run("approval evidence decision is typed", func(t *testing.T) {
		e := evidence
		e.Decision = "maybe"
		mustContainError(t, e.Validate(), "decision")
	})
}

func TestContractEvidenceReadRequest(t *testing.T) {
	request := EvidenceReadRequest{
		RequestID:          "req-5",
		TraceID:            "trace-5",
		BusinessContextRef: "wc_0123456789abcdef",
		EvidenceRef:        "evd_0123456789abcdef",
		Fields:             []string{"employee_name"},
		Purpose:            "read the approver chain evidence",
		ExpiresAt:          contractNow.Add(10 * time.Minute),
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("canonical evidence read request must validate, got %v", err)
	}
	cases := []struct {
		name    string
		mutate  func(*EvidenceReadRequest)
		wantErr string
	}{
		{"missing request id", func(r *EvidenceReadRequest) { r.RequestID = "" }, "request_id"},
		{"missing business context", func(r *EvidenceReadRequest) { r.BusinessContextRef = "" }, "business_context_ref"},
		{"non-opaque business context", func(r *EvidenceReadRequest) { r.BusinessContextRef = "ticket-9" }, "business_context_ref"},
		{"missing evidence ref", func(r *EvidenceReadRequest) { r.EvidenceRef = "" }, "evidence_ref"},
		{"connector-flavored evidence ref", func(r *EvidenceReadRequest) { r.EvidenceRef = "postgres://hr/employees" }, "evidence_ref"},
		{"missing purpose", func(r *EvidenceReadRequest) { r.Purpose = "" }, "purpose"},
		{"missing expiry", func(r *EvidenceReadRequest) { r.ExpiresAt = time.Time{} }, "expires_at"},
		{"negative max results", func(r *EvidenceReadRequest) { r.Constraints = &Constraints{MaxResults: -1} }, "max_results"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := request
			tc.mutate(&r)
			mustContainError(t, r.Validate(), tc.wantErr)
		})
	}
	t.Run("rejects trusted identity in JSON", func(t *testing.T) {
		raw := []byte(`{"request_id":"req-5","business_context_ref":"wc_0123456789abcdef","evidence_ref":"evd_0123456789abcdef","purpose":"p","actor_user_id":"u-1"}`)
		_, err := DecodeEvidenceReadRequest(raw)
		mustContainError(t, err, "actor_user_id")
	})
	t.Run("canonical JSON decodes", func(t *testing.T) {
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEvidenceReadRequest(raw); err != nil {
			t.Fatalf("canonical evidence read request JSON must decode, got %v", err)
		}
	})
}

func TestContractBuildParametersMarshalStableHashing(t *testing.T) {
	// HTML-relevant bytes are the trap: encoding/json re-emits <, > and & as
	// \u-escapes when the enclosing request is marshaled, so only
	// marshal-stable parameter bytes keep their hash across the round trip.
	parameters, parameterHash, err := BuildParameters(map[string]any{
		"note":   `<b>approve & "ship"</b>`,
		"amount": 125000.5,
	})
	if err != nil {
		t.Fatalf("BuildParameters: %v", err)
	}
	if HashParameters(parameters) != parameterHash {
		t.Fatal("BuildParameters must hash exactly the bytes it returns")
	}
	request := validActionRequest()
	request.Parameters = parameters
	request.ParameterHash = parameterHash
	request.RiskDecision.ParameterHash = parameterHash
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeActionRequest(raw)
	if err != nil {
		t.Fatalf("marshal-stable parameters must survive the round trip, got %v", err)
	}
	if decoded.ParameterHash != parameterHash {
		t.Fatal("parameter hash changed across the round trip")
	}

	// The trap itself, demonstrated: hand-built bytes containing a raw '<'
	// are NOT marshal-stable; the enclosing marshal rewrites them and the
	// hash binding breaks on decode.
	handBuilt := json.RawMessage(`{"note":"<b>"}`)
	trap := validActionRequest()
	trap.Parameters = handBuilt
	trap.ParameterHash = HashParameters(handBuilt)
	trap.RiskDecision.ParameterHash = trap.ParameterHash
	rawTrap, err := json.Marshal(trap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeActionRequest(rawTrap); err == nil {
		t.Fatal("hand-built non-marshal-stable bytes must break the hash binding (this is the documented trap)")
	}

	if _, _, err := BuildParameters([]int{1, 2}); err == nil {
		t.Fatal("BuildParameters must reject non-object payloads")
	}
	if _, _, err := BuildParameters(func() {}); err == nil {
		t.Fatal("BuildParameters must surface marshal errors")
	}
}

func TestContractParametersMustBeJSONObjects(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"array", `[1,2]`},
		{"string", `"parameters"`},
		{"number", `42`},
		{"truncated object", `{"a":`},
	} {
		t.Run("parameters "+tc.name, func(t *testing.T) {
			request := validActionRequest()
			request.Parameters = json.RawMessage(tc.raw)
			request.ParameterHash = HashParameters(request.Parameters)
			request.RiskDecision.ParameterHash = request.ParameterHash
			mustContainError(t, request.Validate(), "parameters")
		})
	}
	t.Run("receipt result must be an object", func(t *testing.T) {
		result := json.RawMessage(`[1]`)
		receipt := ActionReceipt{
			ReceiptRef:    "rcp_0123456789abcdef",
			ActionRef:     "act_0123456789abcdef",
			Status:        StatusSucceeded,
			Capability:    "erp.purchase_order.approve",
			ParameterHash: HashParameters([]byte("p")),
			ReceiptSchema: "receipt.erp.purchase_order.approve.v1",
			Result:        result,
			ResultHash:    HashParameters(result),
			IssuedAt:      contractNow,
		}
		mustContainError(t, receipt.Validate(), "result")
	})
	t.Run("action request constraints are validated", func(t *testing.T) {
		request := validActionRequest()
		request.Constraints = &Constraints{MaxResults: -5}
		mustContainError(t, request.Validate(), "max_results")
	})
}

func TestContractActionStatusFrozenStates(t *testing.T) {
	frozen := []ActionStatus{
		StatusRequested, StatusAwaitingApproval, StatusGranted, StatusDispatched,
		StatusExecuting, StatusSucceeded, StatusFailed, StatusResultUnknown,
		StatusReconciling, StatusCompensating, StatusHumanTakeover,
	}
	wantLiterals := []string{
		"requested", "awaiting_approval", "granted", "dispatched", "executing",
		"succeeded", "failed", "result_unknown", "reconciling", "compensating",
		"human_takeover",
	}
	if len(frozen) != len(wantLiterals) {
		t.Fatalf("frozen state count = %d, want %d", len(frozen), len(wantLiterals))
	}
	for i, status := range frozen {
		if string(status) != wantLiterals[i] {
			t.Fatalf("state %d = %q, want %q", i, status, wantLiterals[i])
		}
		if !status.Valid() {
			t.Fatalf("frozen state %q must be valid", status)
		}
	}
	if got := ActionStatuses(); !reflect.DeepEqual(got, frozen) {
		t.Fatalf("ActionStatuses() = %v, want frozen order %v", got, frozen)
	}
	for _, invalid := range []ActionStatus{"", "cancelled", "waiting_confirmation", "REQUESTED"} {
		if invalid.Valid() {
			t.Fatalf("status %q must be invalid", invalid)
		}
	}
}

func TestContractActionAndReceipt(t *testing.T) {
	action := Action{
		ActionRef:          "act_0123456789abcdef",
		Status:             StatusExecuting,
		BusinessContextRef: "wc_0123456789abcdef",
		Capability:         "erp.purchase_order.approve",
		ParameterHash:      HashParameters([]byte("p")),
		GrantRef:           "grant_0123456789abcdef",
		UpdatedAt:          contractNow,
	}
	if err := action.Validate(); err != nil {
		t.Fatalf("canonical action must validate, got %v", err)
	}
	t.Run("action requires typed status", func(t *testing.T) {
		a := action
		a.Status = "running"
		mustContainError(t, a.Validate(), "status")
	})
	t.Run("action ref is an opaque handle", func(t *testing.T) {
		a := action
		a.ActionRef = "42"
		mustContainError(t, a.Validate(), "action_ref")
	})

	result := json.RawMessage(`{"erp_document":"4500012345"}`)
	receipt := ActionReceipt{
		ReceiptRef:    "rcp_0123456789abcdef",
		ActionRef:     "act_0123456789abcdef",
		Status:        StatusSucceeded,
		Capability:    "erp.purchase_order.approve",
		ParameterHash: HashParameters([]byte("p")),
		ReceiptSchema: "receipt.erp.purchase_order.approve.v1",
		Result:        result,
		ResultHash:    HashParameters(result),
		IssuedAt:      contractNow,
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("canonical receipt must validate, got %v", err)
	}
	t.Run("receipt requires schema", func(t *testing.T) {
		r := receipt
		r.ReceiptSchema = ""
		mustContainError(t, r.Validate(), "receipt_schema")
	})
	t.Run("receipt result is hash bound", func(t *testing.T) {
		r := receipt
		r.ResultHash = HashParameters([]byte("tampered"))
		mustContainError(t, r.Validate(), "result_hash")
	})
}

func TestContractAuditEventBinding(t *testing.T) {
	event := AuditEvent{
		EventID:             "evt-1",
		TenantRef:           "tnt_0123456789abcdef",
		TenantSeq:           42,
		BusinessContextRef:  "wc_0123456789abcdef",
		PrincipalRef:        "prn_0123456789abcdef",
		AgentClientRef:      "agc_0123456789abcdef",
		AgentReleaseRef:     "agr_0123456789abcdef",
		OrgSnapshotRef:      "org_0123456789abcdef",
		Capability:          "erp.purchase_order.approve",
		ParameterHash:       HashParameters([]byte("p")),
		RiskDecisionRef:     "rsk_0123456789abcdef",
		ApprovalEvidenceRef: "apv_0123456789abcdef",
		GrantRef:            "grant_0123456789abcdef",
		ActionRef:           "act_0123456789abcdef",
		StatusFrom:          StatusGranted,
		StatusTo:            StatusDispatched,
		ReceiptRef:          "rcp_0123456789abcdef",
		OccurredAt:          contractNow,
		PrevHash:            HashParameters([]byte("previous-event")),
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("canonical audit event must validate, got %v", err)
	}
	t.Run("requires tenant sequence", func(t *testing.T) {
		e := event
		e.TenantSeq = 0
		mustContainError(t, e.Validate(), "tenant_seq")
	})
	t.Run("requires tenant ref", func(t *testing.T) {
		e := event
		e.TenantRef = ""
		mustContainError(t, e.Validate(), "tenant_ref")
	})
	t.Run("prev hash format", func(t *testing.T) {
		e := event
		e.PrevHash = "not-a-digest"
		mustContainError(t, e.Validate(), "prev_hash")
	})
	t.Run("transition must be typed", func(t *testing.T) {
		e := event
		e.StatusTo = "done"
		mustContainError(t, e.Validate(), "status_to")
	})
}

func TestContractPrincipalContextFromVerifiedCredentialsOnly(t *testing.T) {
	principal := PrincipalContext{
		TenantRef:       "tnt_0123456789abcdef",
		PrincipalRef:    "prn_0123456789abcdef",
		AgentClientRef:  "agc_0123456789abcdef",
		AgentReleaseRef: "agr_0123456789abcdef",
		TrustClass:      TrustFirstParty,
		OrgSnapshotRef:  "org_0123456789abcdef",
		VerifiedAt:      contractNow,
		ExpiresAt:       contractNow.Add(time.Hour),
	}
	if err := principal.Validate(); err != nil {
		t.Fatalf("verified principal context must validate, got %v", err)
	}
	for _, tc := range []struct {
		name    string
		mutate  func(*PrincipalContext)
		wantErr string
	}{
		{"missing tenant", func(p *PrincipalContext) { p.TenantRef = "" }, "tenant_ref"},
		{"missing principal", func(p *PrincipalContext) { p.PrincipalRef = "" }, "principal_ref"},
		{"missing agent client", func(p *PrincipalContext) { p.AgentClientRef = "" }, "agent_client_ref"},
		{"missing agent release", func(p *PrincipalContext) { p.AgentReleaseRef = "" }, "agent_release_ref"},
		{"missing org snapshot", func(p *PrincipalContext) { p.OrgSnapshotRef = "" }, "org_snapshot_ref"},
		{"unknown trust class", func(p *PrincipalContext) { p.TrustClass = "vip" }, "trust_class"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := principal
			tc.mutate(&p)
			mustContainError(t, p.Validate(), tc.wantErr)
		})
	}
	for _, class := range []TrustClass{TrustFirstParty, TrustCertifiedThirdParty, TrustUntrusted} {
		if !class.Valid() {
			t.Fatalf("trust class %q must be valid", class)
		}
	}
	if TrustClass("agentatlas").Valid() {
		t.Fatal("vendor names are not trust classes; the trust plane is vendor neutral")
	}
}

// TestContractNoTrustedIdentityFieldsInTypes proves at the type level that no
// public DTO can even represent caller-supplied trusted identity or connector
// topology: no JSON tag is enterprise_id/actor_user_id/connector_instance_id,
// none contains "enterprise", and none starts with "connector_".
func TestContractNoTrustedIdentityFieldsInTypes(t *testing.T) {
	types := []any{
		PrincipalContext{}, Constraints{}, DataNeed{}, EvidenceRequest{}, EvidenceReadRequest{},
		EvidenceHandle{}, BusinessCapabilityRequest{}, ActionRequest{}, Action{}, Precondition{},
		RiskDecision{}, Signature{}, ApprovalPlanRef{}, ApprovalRequest{}, ApprovalEvidence{},
		StepGrant{}, ActionReceipt{}, AuditEvent{},
	}
	forbidden := map[string]bool{
		"enterprise_id": true, "actor_user_id": true, "connector_instance_id": true,
	}
	var walk func(t *testing.T, typ reflect.Type, owner string)
	walk = func(t *testing.T, typ reflect.Type, owner string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ == reflect.TypeOf(time.Time{}) {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "" || tag == "-" {
				t.Errorf("%s.%s must declare an explicit json tag", owner, field.Name)
				continue
			}
			if forbidden[tag] || strings.Contains(tag, "enterprise") || strings.HasPrefix(tag, "connector_") {
				t.Errorf("%s.%s json tag %q leaks trusted identity or connector topology", owner, field.Name, tag)
			}
			walk(t, field.Type, owner+"."+field.Name)
		}
	}
	for _, value := range types {
		typ := reflect.TypeOf(value)
		walk(t, typ, typ.Name())
	}
}

func TestContractHashAndHandleFormats(t *testing.T) {
	hash := HashParameters([]byte(`{"a":1}`))
	if err := ValidateSHA256Ref(hash); err != nil {
		t.Fatalf("HashParameters must emit a canonical sha256 ref, got %q (%v)", hash, err)
	}
	if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Fatalf("hash format = %q, want sha256:<64 hex>", hash)
	}
	if HashParameters([]byte(`{"a":1}`)) != hash {
		t.Fatal("HashParameters must be deterministic")
	}
	if HashParameters([]byte(`{"a": 1}`)) == hash {
		t.Fatal("HashParameters binds exact bytes; formatting changes must change the hash")
	}
	for _, invalid := range []string{
		"",
		"sha256:",
		"sha256:ZZ",
		"md5:" + strings.Repeat("a", 64),
		strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 63), // short by one
		"sha256:" + strings.Repeat("a", 65), // overlength
		"sha256:" + strings.Repeat("a", 64) + "zz", // trailing junk
		"sha256:" + strings.Repeat("A", 64),        // uppercase hex
		" sha256:" + strings.Repeat("a", 64),       // leading junk
	} {
		if err := ValidateSHA256Ref(invalid); err == nil {
			t.Fatalf("digest %q must be rejected", invalid)
		}
	}
	if err := ValidateHandle("wc_0123456789abcdef", HandleWorkCase); err != nil {
		t.Fatalf("valid handle rejected: %v", err)
	}
	for _, invalid := range []string{"", "wc_", "wc_short", "evd_0123456789abcdef", "wc_" + strings.Repeat("a", 200), "wc_0123456789abcde!"} {
		if err := ValidateHandle(invalid, HandleWorkCase); err == nil {
			t.Fatalf("handle %q must be rejected for prefix %q", invalid, HandleWorkCase)
		}
	}
}

func TestContractLengthBoundaries(t *testing.T) {
	t.Run("capability at 256 bytes passes", func(t *testing.T) {
		request := validActionRequest()
		capability := "a." + strings.Repeat("b", 254) // 256 bytes total
		request.Capability = capability
		request.RiskDecision.Capability = capability
		if err := request.Validate(); err != nil {
			t.Fatalf("256-byte capability must pass, got %v", err)
		}
	})
	t.Run("capability over 256 bytes fails", func(t *testing.T) {
		request := validActionRequest()
		capability := "a." + strings.Repeat("b", 255) // 257 bytes total
		request.Capability = capability
		request.RiskDecision.Capability = capability
		mustContainError(t, request.Validate(), "capability")
	})
	t.Run("idempotency key at 128 bytes passes", func(t *testing.T) {
		request := validActionRequest()
		request.IdempotencyKey = strings.Repeat("k", 128)
		if err := request.Validate(); err != nil {
			t.Fatalf("128-byte idempotency key must pass, got %v", err)
		}
	})
	t.Run("idempotency key over 128 bytes fails", func(t *testing.T) {
		request := validActionRequest()
		request.IdempotencyKey = strings.Repeat("k", 129)
		mustContainError(t, request.Validate(), "idempotency_key")
	})
	t.Run("request id at 128 bytes passes", func(t *testing.T) {
		request := validActionRequest()
		request.RequestID = strings.Repeat("r", 128)
		if err := request.Validate(); err != nil {
			t.Fatalf("128-byte request id must pass, got %v", err)
		}
	})
}
