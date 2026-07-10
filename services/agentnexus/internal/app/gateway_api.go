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
	return browserRequestDeadline(browserResponseHeaders(mux), timeout), nil
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
	return path == "/.well-known/openid-configuration" || strings.HasPrefix(path, "/oauth2/") || strings.HasPrefix(path, "/v1/browser-sessions/")
}

func browserResponseHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/oauth2/") {
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
