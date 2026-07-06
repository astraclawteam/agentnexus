package app

import "testing"

func TestRequestContextParsesRequiredFields(t *testing.T) {
	ctx, err := ParseRequestContext(map[string]string{
		"enterprise_id": "ent_123",
		"actor_user_id": "user_456",
		"request_id":    "req_789",
		"trace_id":      "trace_abc",
	})
	if err != nil {
		t.Fatalf("ParseRequestContext returned error: %v", err)
	}

	if ctx.EnterpriseID != "ent_123" {
		t.Fatalf("EnterpriseID = %q, want %q", ctx.EnterpriseID, "ent_123")
	}
	if ctx.ActorUserID != "user_456" {
		t.Fatalf("ActorUserID = %q, want %q", ctx.ActorUserID, "user_456")
	}
	if ctx.RequestID != "req_789" {
		t.Fatalf("RequestID = %q, want %q", ctx.RequestID, "req_789")
	}
	if ctx.TraceID != "trace_abc" {
		t.Fatalf("TraceID = %q, want %q", ctx.TraceID, "trace_abc")
	}
}

func TestRequestContextRequiresEnterpriseID(t *testing.T) {
	_, err := ParseRequestContext(map[string]string{
		"actor_user_id": "user_456",
		"request_id":    "req_789",
	})
	if err == nil {
		t.Fatal("ParseRequestContext returned nil error, want missing enterprise_id error")
	}
	if got, want := err.Error(), "enterprise_id is required"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}
