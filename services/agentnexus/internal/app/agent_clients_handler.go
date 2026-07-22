package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/agenttrust"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

// maxAgentClientRequestBytes bounds a registry request body. A certification is
// the largest of the three (a signing key, a signature and a capability
// ceiling), and none of them carries content.
const maxAgentClientRequestBytes = 32 << 10

// maxCapabilityCeilingEntries bounds a certification's capability ceiling. The
// contract does not cap the array, and an unbounded ceiling would be a cheap way
// to make one row expensive to store and evaluate forever (revisions are
// immutable, so an oversized one can never be edited down).
const maxCapabilityCeilingEntries = 256

// maxCertificationTTLSeconds is the contract's ttl_seconds ceiling (one year).
const maxCertificationTTLSeconds = 31536000

// AgentTrustRegistry is the Agent-client trust registry consumed by the gateway
// (implemented by *agenttrust.Service). The tenant always comes from the
// verified service credential; no operation takes one from the request.
type AgentTrustRegistry interface {
	Register(ctx context.Context, tenantRef string, in agenttrust.RegisterInput) (agenttrust.AgentClient, error)
	ResolveClient(ctx context.Context, tenantRef, agentClientID string) (agenttrust.AgentClient, error)
	ResolveCertification(ctx context.Context, tenantRef, certificationID string) (agenttrust.Certification, error)
	Certify(ctx context.Context, tenantRef string, in agenttrust.CertifyInput) (agenttrust.Certification, error)
	Revoke(ctx context.Context, tenantRef, certificationID, reason string) (agenttrust.StatusChange, error)
}

// agentClientsHandler serves the contract v1.1.0 (GA Task 0C) trust-registry
// operations: registerAgentClient, certifyAgentClient and
// revokeAgentCertification.
//
// All three are first-party administration under trustedServiceSecret only. A
// browser session, an Access Ticket or a Step Grant is refused even though the
// ingress resolver accepts those credentials elsewhere: certifying a client is
// an act of the certifying AUTHORITY, never of an end user acting through a
// console.
type agentClientsHandler struct {
	enterpriseID string
	registry     AgentTrustRegistry
	audit        BrowserAuditSink
	logger       *slog.Logger
}

func newAgentClientsHandler(enterpriseID string, registry AgentTrustRegistry, audit BrowserAuditSink, logger *slog.Logger) (*agentClientsHandler, error) {
	if enterpriseID == "" || registry == nil {
		return nil, errors.New("agent client registry dependencies incomplete")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &agentClientsHandler{enterpriseID: enterpriseID, registry: registry, audit: audit, logger: logger}, nil
}

func (h *agentClientsHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/agent-clients", h.registerClient)
	mux.HandleFunc("POST /v1/agent-clients/{agent_client_ref}/certifications", h.certify)
	mux.HandleFunc("POST /v1/agent-clients/{agent_client_ref}/certifications/{certification_ref}/revocations", h.revoke)
}

// agentClientsProtectedPath reports whether a path belongs to the trust-registry
// subtree, so the ingress resolver binds a trusted context before any handler
// runs. It matches the collection and its subtree exactly rather than by bare
// prefix: an unrelated path that merely starts with the same characters must
// keep answering 404, not 401.
func agentClientsProtectedPath(path string) bool {
	return path == "/v1/agent-clients" || strings.HasPrefix(path, "/v1/agent-clients/")
}

// serviceCredential returns the verified first-party service context, or the
// status to refuse with. It is the single authorization gate of this surface.
func (h *agentClientsHandler) serviceCredential(r *http.Request) (trust.Context, int) {
	trustedCtx, status := trustedRequestContext(r)
	if status != 0 {
		return trust.Context{}, status
	}
	if trustedCtx.Source != trust.SourceServiceCredential || trustedCtx.Principal.TenantRef != h.enterpriseID {
		return trust.Context{}, http.StatusUnauthorized
	}
	return trustedCtx, 0
}

func (h *agentClientsHandler) registerClient(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	trustedCtx, status := h.serviceCredential(r)
	if status != 0 {
		writeRequestFailed(w, status)
		return
	}
	fields, ok := decodeUniqueJSONObject(w, r, maxAgentClientRequestBytes)
	if !ok {
		return
	}
	var body struct {
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
		Publisher string `json:"publisher"`
		Product   string `json:"product"`
		Origin    string `json:"origin"`
	}
	if !h.decodeMembers(r, trustedCtx, fields,
		map[string]any{"request_id": &body.RequestID, "publisher": &body.Publisher, "product": &body.Product},
		map[string]any{"trace_id": &body.TraceID, "origin": &body.Origin}) {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	if _, err := NewRequestContext(trustedCtx, body.RequestID, body.TraceID); err != nil {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	if !boundedText(body.Publisher, 256, false) || !boundedText(body.Product, 256, false) || !boundedText(body.Origin, 128, true) {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	// Calling this operation IS the enterprise-registration act: the summary in
	// the published contract says so, and there is no field for a caller to
	// claim it separately. It grants no trust class on its own — it only makes
	// first_party_trusted reachable by a later certification.
	client, err := h.registry.Register(r.Context(), trustedCtx.Principal.TenantRef, agenttrust.RegisterInput{
		Publisher:            body.Publisher,
		Product:              body.Product,
		Origin:               body.Origin,
		EnterpriseRegistered: true,
	})
	if err != nil {
		h.writeRegistryError(w, r, "register", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent_client_ref": client.ID,
		"publisher":        client.Publisher,
		"product":          client.Product,
		"registered":       true,
	})
}

func (h *agentClientsHandler) certify(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	trustedCtx, status := h.serviceCredential(r)
	if status != 0 {
		writeRequestFailed(w, status)
		return
	}
	fields, ok := decodeUniqueJSONObject(w, r, maxAgentClientRequestBytes)
	if !ok {
		return
	}
	var body struct {
		RequestID                 string               `json:"request_id"`
		TraceID                   string               `json:"trace_id"`
		TrustClass                string               `json:"trust_class"`
		VersionRange              runtime.VersionRange `json:"version_range"`
		SigningKey                runtime.SigningKey   `json:"signing_key"`
		ReleaseManifestDigest     string               `json:"release_manifest_digest"`
		ManifestSignature         runtime.Signature    `json:"manifest_signature"`
		CapabilityCeiling         []string             `json:"capability_ceiling"`
		CertifiedDecisionProvider bool                 `json:"certified_decision_provider"`
		TTLSeconds                int64                `json:"ttl_seconds"`
	}
	if !h.decodeMembers(r, trustedCtx, fields,
		map[string]any{
			"request_id": &body.RequestID, "trust_class": &body.TrustClass,
			"version_range": &body.VersionRange, "signing_key": &body.SigningKey,
			"release_manifest_digest": &body.ReleaseManifestDigest, "manifest_signature": &body.ManifestSignature,
			"capability_ceiling": &body.CapabilityCeiling, "ttl_seconds": &body.TTLSeconds,
		},
		map[string]any{"trace_id": &body.TraceID, "certified_decision_provider": &body.CertifiedDecisionProvider}) {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	if _, err := NewRequestContext(trustedCtx, body.RequestID, body.TraceID); err != nil {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	// untrusted is the ABSENCE of a certification and is never certifiable, so
	// it is not in the request enum. The registry rejects it too; refusing here
	// keeps the transport honest about the frozen enum.
	trustClass := runtime.TrustClass(body.TrustClass)
	if trustClass != runtime.TrustFirstParty && trustClass != runtime.TrustCertifiedThirdParty {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	if body.TTLSeconds < 1 || body.TTLSeconds > maxCertificationTTLSeconds || len(body.CapabilityCeiling) > maxCapabilityCeilingEntries {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}

	client, err := h.registry.ResolveClient(r.Context(), trustedCtx.Principal.TenantRef, r.PathValue("agent_client_ref"))
	if err != nil {
		h.writeRegistryError(w, r, "certify", err)
		return
	}
	// Verify the signed build manifest BEFORE attesting it to the registry. The
	// registry stores SignedBuildManifest as an attested fact and does not
	// re-derive it, so this is the only place the attestation is earned: an
	// unverifiable signature is a rejected certification, never a certification
	// with the flag quietly cleared.
	if err := agenttrust.VerifyBuildManifestSignature(body.SigningKey, body.ReleaseManifestDigest, body.ManifestSignature); err != nil {
		h.logger.WarnContext(r.Context(), "agent_clients.manifest_signature_rejected",
			slog.String("tenant_ref", trustedCtx.Principal.TenantRef),
			slog.String("agent_client_ref", client.ID),
			slog.String("signing_key_id", body.SigningKey.KeyID),
		)
		auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "agent_certification.manifest_signature_rejected")
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}

	certification, err := h.registry.Certify(r.Context(), trustedCtx.Principal.TenantRef, agenttrust.CertifyInput{
		Publisher:                 client.Publisher,
		Product:                   client.Product,
		VersionRange:              body.VersionRange,
		SigningKey:                body.SigningKey,
		ReleaseManifestDigest:     body.ReleaseManifestDigest,
		TrustClass:                trustClass,
		CapabilityCeiling:         body.CapabilityCeiling,
		SignedBuildManifest:       true,
		CertifiedDecisionProvider: body.CertifiedDecisionProvider,
		TTL:                       time.Duration(body.TTLSeconds) * time.Second,
	})
	if err != nil {
		h.writeRegistryError(w, r, "certify", err)
		return
	}
	ceiling := []string(certification.Binding.CapabilityCeiling)
	if ceiling == nil {
		// The response schema requires the member; an absent ceiling is an empty
		// one, not a null.
		ceiling = []string{}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"certification_ref":  certification.ID,
		"trust_class":        string(certification.Binding.TrustClass),
		"revision":           certification.Revision,
		"status":             string(agenttrust.StatusActive),
		"capability_ceiling": ceiling,
		"expires_at":         certification.ExpiresAt.UTC(),
	})
}

func (h *agentClientsHandler) revoke(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	trustedCtx, status := h.serviceCredential(r)
	if status != 0 {
		writeRequestFailed(w, status)
		return
	}
	fields, ok := decodeUniqueJSONObject(w, r, maxAgentClientRequestBytes)
	if !ok {
		return
	}
	var body struct {
		RequestID string `json:"request_id"`
		TraceID   string `json:"trace_id"`
		Reason    string `json:"reason"`
	}
	if !h.decodeMembers(r, trustedCtx, fields,
		map[string]any{"request_id": &body.RequestID, "reason": &body.Reason},
		map[string]any{"trace_id": &body.TraceID}) {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	if _, err := NewRequestContext(trustedCtx, body.RequestID, body.TraceID); err != nil {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}
	if !boundedText(body.Reason, 1024, false) {
		writeRequestFailed(w, http.StatusBadRequest)
		return
	}

	// The certification is addressed UNDER a client, so the lineage the URL
	// asserts has to be the lineage that was recorded: a certification_ref
	// belonging to a different client of the same tenant is a 404 here, not a
	// revocation of somebody else's revision through a mismatched path.
	client, err := h.registry.ResolveClient(r.Context(), trustedCtx.Principal.TenantRef, r.PathValue("agent_client_ref"))
	if err != nil {
		h.writeRegistryError(w, r, "revoke", err)
		return
	}
	certificationRef := r.PathValue("certification_ref")
	certification, err := h.registry.ResolveCertification(r.Context(), trustedCtx.Principal.TenantRef, certificationRef)
	if err != nil {
		h.writeRegistryError(w, r, "revoke", err)
		return
	}
	if certification.AgentClientID != client.ID {
		writeRequestFailed(w, http.StatusNotFound)
		return
	}
	change, err := h.registry.Revoke(r.Context(), trustedCtx.Principal.TenantRef, certificationRef, body.Reason)
	if err != nil {
		h.writeRegistryError(w, r, "revoke", err)
		return
	}
	h.logger.InfoContext(r.Context(), "agent_clients.certification_revoked",
		slog.String("tenant_ref", trustedCtx.Principal.TenantRef),
		slog.String("agent_client_ref", client.ID),
		slog.String("certification_ref", certificationRef),
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"certification_ref": certificationRef,
		"status":            string(agenttrust.StatusRevoked),
		"revoked_at":        change.CreatedAt.UTC(),
	})
}

// decodeMembers applies the contract's additionalProperties: false rule. Every
// required member must be present, optional members may be absent, and anything
// else is refused — a member carrying trusted identity is refused AND audited,
// because that is an attempt to supply identity outside credentials rather than
// an ordinary typo.
func (h *agentClientsHandler) decodeMembers(r *http.Request, trustedCtx trust.Context, fields map[string]json.RawMessage, required, optional map[string]any) bool {
	for key := range fields {
		_, isRequired := required[key]
		_, isOptional := optional[key]
		if isRequired || isOptional {
			continue
		}
		if trust.ForgedIdentityField(key) {
			auditTrustViolation(r.Context(), h.audit, trustedCtx.Principal.TenantRef, trustedCtx.Principal.PrincipalRef, "trusted_context.forged_body_field")
		}
		return false
	}
	for key, target := range required {
		raw, present := fields[key]
		if !present || strictUnmarshal(raw, target) != nil {
			return false
		}
	}
	for key, target := range optional {
		if raw, present := fields[key]; present && strictUnmarshal(raw, target) != nil {
			return false
		}
	}
	return true
}

// strictUnmarshal decodes one member and refuses unknown NESTED members. The
// outer object's exact shape is checked by decodeMembers, but version_range,
// signing_key and manifest_signature are objects of their own and the contract
// declares additionalProperties: false on each; a plain json.Unmarshal would
// silently accept a member the schema forbids.
func strictUnmarshal(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("member carries trailing content")
	}
	return nil
}

// writeRegistryError maps registry outcomes onto the contract's statuses. An
// unknown handle is 404, a rejected certification or malformed input is 400 and
// everything else is a retryable 503 — the cause never reaches the caller, so it
// is logged here instead.
func (h *agentClientsHandler) writeRegistryError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	switch {
	case errors.Is(err, agenttrust.ErrNotFound):
		writeRequestFailed(w, http.StatusNotFound)
	case errors.Is(err, agenttrust.ErrCertificationRejected), errors.Is(err, agenttrust.ErrInvalidInput):
		writeRequestFailed(w, http.StatusBadRequest)
	default:
		h.logger.WarnContext(r.Context(), "agent_clients.registry_unavailable",
			slog.String("operation", operation),
			slog.String("path", r.URL.Path),
			slog.String("error", err.Error()),
		)
		writeRequestFailed(w, http.StatusServiceUnavailable)
	}
}
