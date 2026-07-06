package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

type Identity struct {
	AgentID      string
	EnterpriseID string
	DisplayName  string
}

type RegistrationRequest struct {
	AgentID      string    `json:"agent_id"`
	EnterpriseID string    `json:"enterprise_id"`
	DisplayName  string    `json:"display_name"`
	IssuedAt     time.Time `json:"issued_at"`
	Signature    string    `json:"signature"`
}

func NewRegistrationRequest(identity Identity, signingKey string) (RegistrationRequest, error) {
	req := RegistrationRequest{
		AgentID:      identity.AgentID,
		EnterpriseID: identity.EnterpriseID,
		DisplayName:  identity.DisplayName,
		IssuedAt:     time.Now().UTC(),
	}
	req.Signature = signRegistration(req, signingKey)
	return req, nil
}

func VerifyRegistrationRequest(req RegistrationRequest, signingKey string) bool {
	expected := signRegistration(req, signingKey)
	return hmac.Equal([]byte(expected), []byte(req.Signature))
}

func signRegistration(req RegistrationRequest, signingKey string) string {
	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(registrationPayload(req)))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func registrationPayload(req RegistrationRequest) string {
	return strings.Join([]string{
		req.AgentID,
		req.EnterpriseID,
		req.DisplayName,
		req.IssuedAt.Format(time.RFC3339Nano),
	}, "\n")
}
