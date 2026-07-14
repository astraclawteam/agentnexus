package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Sentinel errors of the canonical request validation.
var (
	// ErrTrustedIdentityInRequest rejects request JSON that tries to supply
	// trusted identity or connector topology. Trusted identity comes only
	// from verified credentials.
	ErrTrustedIdentityInRequest = errors.New("request JSON must not carry trusted identity or connector topology")
	// ErrLegacyActionShape rejects the retired untyped `action` + `input`
	// request shape. Actions are typed: capability + parameters +
	// parameter_hash.
	ErrLegacyActionShape = errors.New("legacy untyped action+input shape is rejected; use capability, parameters and parameter_hash")
)

// Opaque handle prefixes of the frozen contract. A handle is its kind prefix
// followed by 16..128 characters of [A-Za-z0-9_-]. Handles never encode
// connector instances, endpoints or paths.
const (
	HandleWorkCase         = "wc_"
	HandleEvidence         = "evd_"
	HandleApprovalPlan     = "apl_"
	HandleApprovalEvidence = "apv_"
	HandleGrant            = "grant_"
	HandleAction           = "act_"
	HandleReceipt          = "rcp_"
	// HandleObservation addresses one signed ObservationReceipt (contract
	// v1.3.0, GA Task 0A amendment).
	HandleObservation = "obs_"
)

var (
	sha256RefRe  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	capabilityRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	handleBodyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// HashParameters returns the canonical sha256:<64 hex> digest of the exact
// payload bytes. The contract binds exact bytes: any re-encoding changes the
// hash on purpose.
//
// Client-side trap: when a request struct is marshaled with encoding/json,
// RawMessage content is compacted and HTML-escaped in transit: the bytes
// '<', '>' and '&' are re-emitted as their \u-escaped forms. Hand-built
// bytes that are not already in marshal-stable form therefore change
// between hashing and sending, and the hash binding breaks. Use
// BuildParameters, whose output is a fixed point of encoding/json and
// round-trips unchanged.
func HashParameters(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildParameters marshals v with encoding/json and returns the exact
// payload bytes together with their canonical hash, in one step. The
// returned bytes are compact and HTML-escaped exactly as encoding/json will
// re-emit them inside an enclosing request, so the hash stays valid across
// the round trip. Payloads are JSON objects by contract (ActionRequest
// parameters, ActionReceipt results).
func BuildParameters(v any) (json.RawMessage, string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, "", fmt.Errorf("marshal parameters: %w", err)
	}
	if !isJSONObject(raw) {
		return nil, "", errors.New("hash-bound payloads must be single JSON objects")
	}
	return json.RawMessage(raw), HashParameters(raw), nil
}

// isJSONObject reports whether raw is exactly one valid JSON object.
func isJSONObject(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	return json.Valid(raw)
}

// ValidateSHA256Ref checks the canonical sha256:<64 hex> digest format.
func ValidateSHA256Ref(value string) error {
	if !sha256RefRe.MatchString(value) {
		return fmt.Errorf("%q is not a sha256:<64 hex> digest", value)
	}
	return nil
}

// ValidateHandle checks that handle is an opaque handle of the given kind
// prefix.
func ValidateHandle(handle, prefix string) error {
	if !strings.HasPrefix(handle, prefix) {
		return fmt.Errorf("%q is not an opaque %s* handle", handle, prefix)
	}
	if !handleBodyRe.MatchString(strings.TrimPrefix(handle, prefix)) {
		return fmt.Errorf("%q is not an opaque %s* handle (16..128 chars of [A-Za-z0-9_-] after the prefix)", handle, prefix)
	}
	return nil
}

func fieldErrorf(field, format string, args ...any) error {
	return fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...))
}

func requireNonEmpty(field, value string) error {
	if value == "" {
		return fieldErrorf(field, "is required")
	}
	return nil
}

func validateRequestID(requestID string) error {
	if requestID == "" {
		return fieldErrorf("request_id", "is required")
	}
	if len(requestID) > 128 {
		return fieldErrorf("request_id", "must be at most 128 bytes")
	}
	return nil
}

func validateIdempotencyKey(key string) error {
	if key == "" {
		return fieldErrorf("idempotency_key", "is required")
	}
	if len(key) < 16 || len(key) > 128 {
		return fieldErrorf("idempotency_key", "must be 16..128 bytes")
	}
	return nil
}

func validateCapability(capability string) error {
	if capability == "" {
		return fieldErrorf("capability", "is required")
	}
	if len(capability) > 256 {
		return fieldErrorf("capability", "must be at most 256 bytes")
	}
	if !capabilityRe.MatchString(capability) {
		return fieldErrorf("capability", "%q is not a namespaced business-semantic capability (for example erp.purchase_order.approve)", capability)
	}
	return nil
}

// isForbiddenRequestKey reports whether a request JSON key tries to carry
// trusted identity or connector topology.
//
// Four related, intentionally different forbidden-name sets exist:
//   - this decoder set: request JSON keys (the exact trio plus any key
//     containing "enterprise" or prefixed connector_), skipping hash-bound
//     opaque payloads. org_version/org_unit_id are not listed here because
//     strict decoding (DisallowUnknownFields) already rejects them — no
//     request type declares such a field. Business-outcome names are not
//     listed here either: no request type declares such a field, so strict
//     decoding rejects them, and the type-level walker below makes them
//     unrepresentable;
//   - the service parity test (public_contract_parity_test.go,
//     forbiddenPublicFieldName): additionally bans resource_name and the
//     exact org_unit_id anywhere in the public YAML/proto surface, bans
//     org_version request-side only (it is a legal server-authored response
//     field), and — since contract v1.3.0 (GA Task 0A amendment, plan
//     dc81e80) — bans any schema/field name that is or contains
//     outcome/goal_achieved or is a graph-provider name (graph, graph_*,
//     *_graph) anywhere in the public YAML/proto surface;
//   - the SDK type-walker test (TestContractNoTrustedIdentityFieldsInTypes):
//     checks the Go json tags of every public type, responses included, for
//     both the identity/topology bans and the same v1.3.0 outcome/
//     goal_achieved/graph-provider matcher, keeping tag and contract-file
//     scans in lockstep;
//   - the receipt-scoped tag test
//     (TestContractReceiptsCarryNoBusinessOutcomeAuthority): defense in
//     depth on ActionReceipt/ObservationReceipt — re-applies the outcome
//     matcher and freezes the exact ObservationReceipt tag set, because the
//     receipts are where outcome authority would most plausibly creep in.
func isForbiddenRequestKey(key string) bool {
	switch key {
	case "enterprise_id", "actor_user_id", "connector_instance_id":
		return true
	}
	return strings.Contains(key, "enterprise") || strings.HasPrefix(key, "connector_")
}

// opaquePayloadKeys are hash-bound business payloads: their content is DATA,
// never trust, so key scanning stops at their boundary.
var opaquePayloadKeys = map[string]bool{"parameters": true, "result": true}

func scanForbiddenIdentityKeys(value any) error {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if isForbiddenRequestKey(key) {
				return fmt.Errorf("%w: field %q", ErrTrustedIdentityInRequest, key)
			}
			if opaquePayloadKeys[key] {
				continue
			}
			if err := scanForbiddenIdentityKeys(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := scanForbiddenIdentityKeys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// decodeStrictRequest is the canonical request decoder: it rejects trusted
// identity and connector topology keys, rejects the legacy untyped shape and
// rejects every unknown envelope field.
func decodeStrictRequest(data []byte, out any) error {
	var probe any
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("parse request JSON: %w", err)
	}
	root, ok := probe.(map[string]any)
	if !ok {
		return errors.New("request body must be a JSON object")
	}
	if _, hasAction := root["action"]; hasAction {
		if _, hasInput := root["input"]; hasInput {
			return ErrLegacyActionShape
		}
	}
	if err := scanForbiddenIdentityKeys(root); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	return nil
}

// DecodeActionRequest decodes and canonically validates an ActionRequest.
func DecodeActionRequest(data []byte) (ActionRequest, error) {
	var request ActionRequest
	if err := decodeStrictRequest(data, &request); err != nil {
		return ActionRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return ActionRequest{}, err
	}
	return request, nil
}

// DecodeEvidenceRequest decodes and canonically validates an EvidenceRequest.
func DecodeEvidenceRequest(data []byte) (EvidenceRequest, error) {
	var request EvidenceRequest
	if err := decodeStrictRequest(data, &request); err != nil {
		return EvidenceRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return EvidenceRequest{}, err
	}
	return request, nil
}

// DecodeEvidenceReadRequest decodes and canonically validates an
// EvidenceReadRequest.
func DecodeEvidenceReadRequest(data []byte) (EvidenceReadRequest, error) {
	var request EvidenceReadRequest
	if err := decodeStrictRequest(data, &request); err != nil {
		return EvidenceReadRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return EvidenceReadRequest{}, err
	}
	return request, nil
}

// DecodeBusinessCapabilityRequest decodes and canonically validates a
// BusinessCapabilityRequest.
func DecodeBusinessCapabilityRequest(data []byte) (BusinessCapabilityRequest, error) {
	var request BusinessCapabilityRequest
	if err := decodeStrictRequest(data, &request); err != nil {
		return BusinessCapabilityRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return BusinessCapabilityRequest{}, err
	}
	return request, nil
}

// DecodeApprovalRequest decodes and canonically validates an ApprovalRequest.
func DecodeApprovalRequest(data []byte) (ApprovalRequest, error) {
	var request ApprovalRequest
	if err := decodeStrictRequest(data, &request); err != nil {
		return ApprovalRequest{}, err
	}
	if err := request.Validate(); err != nil {
		return ApprovalRequest{}, err
	}
	return request, nil
}
