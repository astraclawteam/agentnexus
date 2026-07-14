package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func NewGatewayAPIRouter(serviceName, version string) http.Handler {
	return newGatewayAPIMux(serviceName, version)
}

// NewGatewayAPIRouterWithDependencies wires the browser gateway. The trusted
// context is resolved exactly ONCE at ingress by the trust resolver
// middleware: it screens every request for identity-forging headers and
// binds the immutable credential-derived context for the protected runtime
// endpoints. Handlers never authenticate on their own.
func NewGatewayAPIRouterWithDependencies(serviceName, version string, deps BrowserAuthDependencies) (http.Handler, error) {
	mux := newGatewayAPIMux(serviceName, version)
	handler, err := newBrowserAuthHandler(deps)
	if err != nil {
		return nil, err
	}
	handler.register(mux)
	timeout, err := browserRequestTimeout(deps.RequestTimeout)
	if err != nil {
		return nil, err
	}
	chain := handler.trustResolver.Middleware(browserResponseHeaders(mux))
	return browserRequestDeadline(chain, timeout), nil
}

func browserRequestDeadline(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isBrowserAuthPath(r.URL.Path) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}
func isBrowserAuthPath(path string) bool {
	return path == "/.well-known/openid-configuration" || trustProtectedPath(path) || strings.HasPrefix(path, "/oauth2/") || strings.HasPrefix(path, "/v1/browser-sessions/")
}

// trustProtectedPath lists the runtime endpoints that require ONE immutable
// credential-derived trusted context resolved at ingress. The whole
// /v1/approvals/ transmission subtree (transmissions, per-plan status,
// revocations, evidence) is protected by prefix.
func trustProtectedPath(path string) bool {
	switch path {
	case "/v1/authorization/decisions", "/v1/step-grants", "/v1/tickets/verify", "/v1/audit/evidence",
		"/v1/runtime/locate", "/v1/runtime/read":
		return true
	}
	return strings.HasPrefix(path, "/v1/approvals/")
}

func browserResponseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/oauth2/") || trustProtectedPath(r.URL.Path) {
			setNoStore(w)
		}
		next.ServeHTTP(w, r)
	})
}

func newGatewayAPIMux(serviceName, version string) *http.ServeMux {
	mux := http.NewServeMux()
	health := NewHealthStatus(serviceName, version, true)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("GET /api/console/overview", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, NewConsoleOverview(r.URL.Query().Get("locale")))
	})

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
