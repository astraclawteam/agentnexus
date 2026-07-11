package app

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
)

func TestBrowserAuthRejectsInvalidForwardedChainBeforeLimiterOrSessions(t *testing.T) {
	limiter := &stubAuthorizeRateLimiter{}
	var sessions *countingSessionService
	h := newBrowserHarnessWithRateLimit(t, limiter, NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}), func(service *browserauth.Service) BrowserSessionService {
		sessions = &countingSessionService{BrowserSessionService: service}
		return sessions
	})
	target := "/oauth2/authorize?" + h.authorizeQuery("s", "n").Encode()
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
	}{
		{name: "malformed suffix", remoteAddr: "10.0.0.10:1234", xff: "203.0.113.9, garbage, 10.0.0.9"},
		{name: "remote zone", remoteAddr: "[fe80::1%eth0]:1234", xff: "203.0.113.9"},
		{name: "suffix zone", remoteAddr: "10.0.0.10:1234", xff: "203.0.113.9, fe80::1%eth0"},
		{name: "client zone", remoteAddr: "10.0.0.10:1234", xff: "fe80::1%eth0, 10.0.0.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := authorizeFrom(h.router, target, tt.remoteAddr, tt.xff)
			if rr.Code != http.StatusBadRequest || rr.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(rr.Body.String()) != `{"error":"invalid_forwarded_chain"}` {
				t.Fatalf("status=%d cache=%q body=%s", rr.Code, rr.Header().Get("Cache-Control"), rr.Body.String())
			}
			assertNoAuthorizeSideEffects(t, rr)
			if limiter.calls != 0 || sessions.getSessions != 0 || sessions.createAttempts != 0 {
				t.Fatalf("side effects limiter=%d gets=%d attempts=%d", limiter.calls, sessions.getSessions, sessions.createAttempts)
			}
		})
	}
}

func TestBrowserAuthAuthorizeRateLimitCannotBeBypassedWithBrowserIDsOrUntrustedXFF(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 34, 45, 0, time.UTC)
	limiter, err := browserauth.NewMemoryAuthorizeRateLimiter(100, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	var sessions *countingSessionService
	h := newBrowserHarnessWithRateLimit(t, limiter, NewAuthorizeSourceResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}), func(service *browserauth.Service) BrowserSessionService {
		sessions = &countingSessionService{BrowserSessionService: service}
		return sessions
	})
	target := "/oauth2/authorize?" + h.authorizeQuery("s", "n").Encode()
	for i := 0; i < 100; i++ {
		rr := authorizeFrom(h.router, target, "192.0.2.10:1234", "198.51.100."+strconv.Itoa(i+1), &http.Cookie{Name: oidcBrowserCookie, Value: browserIDFixture(byte(i + 1))})
		if rr.Code != http.StatusFound {
			t.Fatalf("request %d status=%d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}
	attemptsBefore := sessions.createAttempts
	rr := authorizeFrom(h.router, target, "192.0.2.10:9876", "203.0.113.250", &http.Cookie{Name: oidcBrowserCookie, Value: browserIDFixture(100)})
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "15" {
		t.Fatalf("status=%d retry=%q body=%s", rr.Code, rr.Header().Get("Retry-After"), rr.Body.String())
	}
	assertNoAuthorizeSideEffects(t, rr)
	if sessions.createAttempts != attemptsBefore {
		t.Fatalf("limited request created attempt: before=%d after=%d", attemptsBefore, sessions.createAttempts)
	}
	rr = authorizeFrom(h.router, target, "192.0.2.11:1234", "", &http.Cookie{Name: oidcBrowserCookie, Value: browserIDFixture(101)})
	if rr.Code != http.StatusFound {
		t.Fatalf("independent source status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestBrowserAuthAuthorizeLimiterUnavailableFailsBeforeSessionBootstrapOrAttempt(t *testing.T) {
	limiter := &stubAuthorizeRateLimiter{err: browserauth.ErrAuthorizeRateUnavailable}
	var sessions *countingSessionService
	h := newBrowserHarnessWithRateLimit(t, limiter, NewAuthorizeSourceResolver(nil), func(service *browserauth.Service) BrowserSessionService {
		sessions = &countingSessionService{BrowserSessionService: service}
		return sessions
	})
	token, _, err := h.sessions.CreateSession(context.Background(), browserauth.CreateSessionInput{EnterpriseID: "ent-1", UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	rr := authorizeFrom(h.router, "/oauth2/authorize?"+h.authorizeQuery("s", "n").Encode(), "192.0.2.10:1234", "", &http.Cookie{Name: browserSessionCookie, Value: token})
	if rr.Code != http.StatusServiceUnavailable || limiter.calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s", rr.Code, limiter.calls, rr.Body.String())
	}
	assertNoAuthorizeSideEffects(t, rr)
	if sessions.getSessions != 0 || sessions.createAttempts != 0 {
		t.Fatalf("session store touched: gets=%d attempts=%d", sessions.getSessions, sessions.createAttempts)
	}
}

func TestBrowserAuthAuthorizeInvalidParametersDoNotConsumeSourceQuota(t *testing.T) {
	limiter := &stubAuthorizeRateLimiter{}
	h := newBrowserHarnessWithRateLimit(t, limiter, NewAuthorizeSourceResolver(nil), func(service *browserauth.Service) BrowserSessionService { return service })
	query := h.authorizeQuery("s", "n")
	query.Set("redirect_uri", "https://evil.example/cb")
	rr := authorizeFrom(h.router, "/oauth2/authorize?"+query.Encode(), "192.0.2.10:1234", "", nil)
	if rr.Code != http.StatusBadRequest || limiter.calls != 0 {
		t.Fatalf("status=%d limiter calls=%d", rr.Code, limiter.calls)
	}
}

type stubAuthorizeRateLimiter struct {
	mu         sync.Mutex
	calls      int
	sourceHash string
	retryAfter time.Duration
	err        error
}

func (l *stubAuthorizeRateLimiter) AllowAuthorize(_ context.Context, _, _, sourceHash string) (time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	l.sourceHash = sourceHash
	return l.retryAfter, l.err
}

func authorizeFrom(handler http.Handler, target, remoteAddr, xff string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func assertNoAuthorizeSideEffects(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Header().Get("Location") != "" || len(rr.Result().Cookies()) != 0 {
		t.Fatalf("limited response location=%q cookies=%v", rr.Header().Get("Location"), rr.Result().Cookies())
	}
}

func browserIDFixture(fill byte) string {
	value := make([]byte, 32)
	for i := range value {
		value[i] = fill
	}
	return base64RawURL(value)
}

func base64RawURL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
