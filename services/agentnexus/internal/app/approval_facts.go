package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approval"
)

const maxFactsAttestationTTL = 5 * time.Minute

type ChangeFactsVerificationInput struct {
	EnterpriseID            string
	ActorUserID             string
	OrgVersion              int64
	OrgUnitID               string
	ResourceType            string
	ResourceID              string
	Action                  string
	ChangedFields           []string
	ImpactedOrgUnitIDs      []string
	ImpactedUserCount       int
	PublishedBehaviorChange bool
	ExternalSideEffect      bool
	FactsIssuedAt           time.Time
	FactsExpiresAt          time.Time
	FactsNonce              string
	IdempotencyKeyHash      string
	Signature               string
}

type ChangeFactsVerifier interface {
	VerifyChangeFacts(context.Context, ChangeFactsVerificationInput) (approval.VerifiedChangeFacts, error)
}

type RejectChangeFactsVerifier struct{}

func (RejectChangeFactsVerifier) VerifyChangeFacts(ctx context.Context, _ ChangeFactsVerificationInput) (approval.VerifiedChangeFacts, error) {
	if err := ctx.Err(); err != nil {
		return approval.VerifiedChangeFacts{}, err
	}
	return approval.NewUnverifiedChangeFacts(approval.RiskReasonUnverifiedChangeFacts), nil
}

type HMACChangeFactsVerifier struct {
	secret []byte
	now    func() time.Time
}

func NewHMACChangeFactsVerifier(secret []byte, now func() time.Time) (*HMACChangeFactsVerifier, error) {
	if len(secret) < 32 || now == nil {
		return nil, errors.New("approval facts verifier unavailable")
	}
	return &HMACChangeFactsVerifier{secret: append([]byte{}, secret...), now: now}, nil
}

func LoadChangeFactsVerifierFromFile(path string, now func() time.Time) (ChangeFactsVerifier, error) {
	if path == "" {
		return RejectChangeFactsVerifier{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("approval facts secret unavailable")
	}
	secret := bytes.TrimSpace(raw)
	verifier, err := NewHMACChangeFactsVerifier(secret, now)
	if err != nil {
		return nil, errors.New("approval facts secret unavailable")
	}
	return verifier, nil
}

func ComputeChangeFactsAttestation(secret []byte, input ChangeFactsVerificationInput) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("approval facts secret too short")
	}
	payload, err := canonicalChangeFacts(input)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func computeApprovalReplayHash(input ChangeFactsVerificationInput, requestedRisk approval.RiskLevel) (string, error) {
	payload, err := canonicalChangeFacts(input)
	if err != nil {
		return "", err
	}
	payloadSum := sha256.Sum256(payload)
	signatureSum := sha256.Sum256([]byte(input.Signature))
	replay, err := json.Marshal(struct {
		PayloadHash   string             `json:"payload_hash"`
		SignatureHash string             `json:"signature_hash"`
		RequestedRisk approval.RiskLevel `json:"requested_risk"`
	}{hex.EncodeToString(payloadSum[:]), hex.EncodeToString(signatureSum[:]), requestedRisk})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(replay)
	return hex.EncodeToString(sum[:]), nil
}

func (v *HMACChangeFactsVerifier) VerifyChangeFacts(ctx context.Context, input ChangeFactsVerificationInput) (approval.VerifiedChangeFacts, error) {
	if err := ctx.Err(); err != nil {
		return approval.VerifiedChangeFacts{}, err
	}
	unverified := approval.NewUnverifiedChangeFacts(approval.RiskReasonUnverifiedChangeFacts)
	if v == nil || len(v.secret) < 32 || v.now == nil {
		return unverified, nil
	}
	payload, err := canonicalChangeFacts(input)
	if err != nil {
		return unverified, nil
	}
	provided, err := base64.RawURLEncoding.DecodeString(input.Signature)
	if err != nil || len(provided) != sha256.Size {
		return unverified, nil
	}
	mac := hmac.New(sha256.New, v.secret)
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(provided, expected) != 1 {
		return unverified, nil
	}
	now := v.now().UTC()
	issued := input.FactsIssuedAt.UTC()
	expires := input.FactsExpiresAt.UTC()
	if issued.After(now.Add(30*time.Second)) || expires.Before(now) || !expires.After(issued) || expires.Sub(issued) > maxFactsAttestationTTL {
		return unverified, nil
	}
	digest := sha256.Sum256(payload)
	return approval.NewVerifiedChangeFacts(approval.VerifiedChangeFactsInput{ChangedFields: input.ChangedFields, ImpactedOrgUnitIDs: input.ImpactedOrgUnitIDs, ImpactedUserCount: input.ImpactedUserCount, PublishedBehaviorChange: input.PublishedBehaviorChange, ExternalSideEffect: input.ExternalSideEffect, Digest: hex.EncodeToString(digest[:])}), nil
}

func canonicalChangeFacts(input ChangeFactsVerificationInput) ([]byte, error) {
	if !canonicalAuthorizationValue(input.EnterpriseID) || !canonicalAuthorizationValue(input.ActorUserID) || input.OrgVersion < 1 || !canonicalAuthorizationValue(input.OrgUnitID) || !canonicalAuthorizationValue(input.ResourceType) || !canonicalAuthorizationValue(input.ResourceID) || !canonicalAuthorizationValue(input.Action) || input.ImpactedUserCount < 0 || !canonicalUniqueStrings(input.ChangedFields) || !canonicalUniqueStrings(input.ImpactedOrgUnitIDs) || len(input.FactsNonce) < 16 || len(input.FactsNonce) > 128 || strings.TrimSpace(input.FactsNonce) != input.FactsNonce || len(input.IdempotencyKeyHash) != 64 {
		return nil, errors.New("invalid approval facts")
	}
	if _, err := hex.DecodeString(input.IdempotencyKeyHash); err != nil {
		return nil, errors.New("invalid idempotency hash")
	}
	changed := append([]string{}, input.ChangedFields...)
	impacted := append([]string{}, input.ImpactedOrgUnitIDs...)
	sort.Strings(changed)
	sort.Strings(impacted)
	payload := struct {
		EnterpriseID            string    `json:"enterprise_id"`
		ActorUserID             string    `json:"actor_user_id"`
		OrgVersion              int64     `json:"org_version"`
		OrgUnitID               string    `json:"org_unit_id"`
		ResourceType            string    `json:"resource_type"`
		ResourceID              string    `json:"resource_id"`
		Action                  string    `json:"action"`
		ChangedFields           []string  `json:"changed_fields"`
		ImpactedOrgUnitIDs      []string  `json:"impacted_org_unit_ids"`
		ImpactedUserCount       int       `json:"impacted_user_count"`
		PublishedBehaviorChange bool      `json:"published_behavior_change"`
		ExternalSideEffect      bool      `json:"external_side_effect"`
		FactsIssuedAt           time.Time `json:"facts_issued_at"`
		FactsExpiresAt          time.Time `json:"facts_expires_at"`
		FactsNonce              string    `json:"facts_nonce"`
		IdempotencyKeyHash      string    `json:"idempotency_key_hash"`
	}{input.EnterpriseID, input.ActorUserID, input.OrgVersion, input.OrgUnitID, input.ResourceType, input.ResourceID, input.Action, changed, impacted, input.ImpactedUserCount, input.PublishedBehaviorChange, input.ExternalSideEffect, input.FactsIssuedAt.UTC(), input.FactsExpiresAt.UTC(), input.FactsNonce, input.IdempotencyKeyHash}
	return json.Marshal(payload)
}
