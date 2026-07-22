package trust_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const rejectedServiceSecret = "Service-Secret-Nobody-Provisioned-9xQ2"

type rejectingServices struct{}

func (rejectingServices) VerifyServiceCredential(_ context.Context, _, _ string) (trust.ServiceIdentity, error) {
	return trust.ServiceIdentity{}, trust.ErrCredentialRejected
}

// A first-party service refused in a permanent retry loop used to produce a
// COMPLETELY SILENT gateway log: rejections reached the audit table and nothing
// else, so an operator watching the service could see only that a status code
// came back. The evidence plane already logs its denials with reasons; ingress
// now does the same, and it names WHICH credential was refused.
func TestRejectedServiceCredentialIsLoggedWithReasonAndClient(t *testing.T) {
	var logged bytes.Buffer
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef: testTenant,
		Services:  rejectingServices{},
		Logger:    slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Protected: func(r *http.Request) bool { return r.URL.Path == "/v1/org-events" },
	})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	router := resolver.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a rejected credential must never reach the handler")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/org-events", nil)
	req.SetBasicAuth("agentatlas", rejectedServiceSecret)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", recorder.Code)
	}
	line := logged.String()
	for _, want := range []string{
		"trust.credential_rejected",
		"reason=credential_rejected",
		"credential_source=service_credential",
		"path=/v1/org-events",
		"claimed_client_id=agentatlas",
		"tenant_ref=" + testTenant,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("rejection log is missing %q; got %q", want, line)
		}
	}
	// The client id is the NON-SECRET half. The secret must never be logged, in
	// any encoding.
	if strings.Contains(line, rejectedServiceSecret) {
		t.Fatal("the rejection log leaked the presented service secret")
	}
}

// The claimed client id is attacker-controlled, so it is screened before it
// reaches a log record: a newline in a log line is a forged second record.
func TestRejectedServiceCredentialNeverEchoesUnprintableClientID(t *testing.T) {
	var logged bytes.Buffer
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef: testTenant,
		Services:  rejectingServices{},
		Logger:    slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Protected: func(r *http.Request) bool { return r.URL.Path == "/v1/org-events" },
	})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	router := resolver.Middleware(http.NotFoundHandler())

	for _, clientID := range []string{
		"agentatlas\nWARN forged=record",
		// Well within what decodeBasicCredential accepts, so it really does reach
		// the log site — and past what a log line may echo.
		strings.Repeat("x", 200),
	} {
		logged.Reset()
		req := httptest.NewRequest(http.MethodGet, "/v1/org-events", nil)
		req.SetBasicAuth(clientID, rejectedServiceSecret)
		router.ServeHTTP(httptest.NewRecorder(), req)
		if !strings.Contains(logged.String(), "claimed_client_id=<non-canonical>") {
			t.Fatalf("unscreened client id reached the log: %q", logged.String())
		}
		if strings.Contains(logged.String(), "forged=record") {
			t.Fatal("a newline in the claimed client id forged a second log record")
		}
	}
}
