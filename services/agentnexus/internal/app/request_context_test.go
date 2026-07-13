package app

import (
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

func trustedContextFixture() trust.Context {
	now := time.Now().UTC()
	return trust.Context{
		Principal: runtime.PrincipalContext{
			TenantRef:       "ent_123",
			PrincipalRef:    "user_456",
			AgentClientRef:  "console",
			AgentReleaseRef: trust.UnregisteredReleaseRef,
			TrustClass:      runtime.TrustFirstParty,
			OrgSnapshotRef:  trust.OrgSnapshotRef(12),
			VerifiedAt:      now,
			ExpiresAt:       now.Add(time.Hour),
		},
		Source:     trust.SourceBrowserSession,
		OrgVersion: 12,
	}
}

func TestRequestContextBindsCredentialDerivedPrincipal(t *testing.T) {
	ctx, err := NewRequestContext(trustedContextFixture(), "req_789", "trace_abc")
	if err != nil {
		t.Fatalf("NewRequestContext returned error: %v", err)
	}
	if ctx.Principal.TenantRef != "ent_123" {
		t.Fatalf("TenantRef = %q, want %q", ctx.Principal.TenantRef, "ent_123")
	}
	if ctx.Principal.PrincipalRef != "user_456" {
		t.Fatalf("PrincipalRef = %q, want %q", ctx.Principal.PrincipalRef, "user_456")
	}
	if ctx.OrgVersion != 12 {
		t.Fatalf("OrgVersion = %d, want 12", ctx.OrgVersion)
	}
	if ctx.RequestID != "req_789" {
		t.Fatalf("RequestID = %q, want %q", ctx.RequestID, "req_789")
	}
	if ctx.TraceID != "trace_abc" {
		t.Fatalf("TraceID = %q, want %q", ctx.TraceID, "trace_abc")
	}
}

func TestRequestContextRejectsUntrustedPrincipal(t *testing.T) {
	// A zero (unverified) principal can never mint a request context: the
	// retired ParseRequestContext accepted caller-supplied enterprise_id /
	// actor_user_id envelope values; that path is gone.
	if _, err := NewRequestContext(trust.Context{}, "req_789", ""); err == nil {
		t.Fatal("NewRequestContext accepted an unverified principal")
	}
}

func TestRequestContextRequiresCanonicalRequestID(t *testing.T) {
	for _, requestID := range []string{"", " req", "req "} {
		if _, err := NewRequestContext(trustedContextFixture(), requestID, ""); err == nil {
			t.Fatalf("request_id %q was accepted", requestID)
		}
	}
}
