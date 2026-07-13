package transportsecurity

import (
	"net/http"
	"testing"
)

// White-box guard (Minor review finding): the pooled HTTP client must NEVER
// hand back a nil transport with a nil error — building http.Client with a
// nil Transport silently falls back to http.DefaultTransport (no client
// certificate, system trust roots), which would be fail-open. The state is
// unreachable through the public constructor (NewHTTPClient validates the
// first rebuild), so it is pinned here at the unexported seam with a client
// whose rebuilds can never produce a transport.
func TestHTTPClientFailsClosedWithoutUsableTransport(t *testing.T) {
	manager := &Manager{} // no material loaded: every rebuild must fail
	client := &HTTPClient{manager: manager, serverName: "localhost"}

	transport, err := client.currentTransport()
	if err == nil {
		t.Fatal("currentTransport returned a nil error without a usable transport")
	}
	if transport != nil {
		t.Fatalf("currentTransport returned a transport (%v) although the rebuild failed", transport)
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:9/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("Do succeeded without a usable transport: this is the fail-open shape via http.DefaultTransport")
	}
}
