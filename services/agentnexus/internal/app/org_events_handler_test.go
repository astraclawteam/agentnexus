package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

const orgEventsTenant = "ent-orgevents"

type fakeOrgEventSource struct {
	latest      int64
	latestErr   error
	events      []OrgEventRecord
	eventsErr   error
	gotTenant   string
	gotSince    int64
	callCount   int
	forceUnavai bool
}

func (s *fakeOrgEventSource) LatestSealedVersion(_ context.Context, tenantRef string) (int64, error) {
	s.gotTenant = tenantRef
	if s.latestErr != nil {
		return 0, s.latestErr
	}
	return s.latest, nil
}

func (s *fakeOrgEventSource) EventsSince(_ context.Context, tenantRef string, since int64, _ int) ([]OrgEventRecord, error) {
	s.callCount++
	s.gotTenant = tenantRef
	s.gotSince = since
	if s.eventsErr != nil {
		return nil, s.eventsErr
	}
	var out []OrgEventRecord
	for _, event := range s.events {
		if event.OrgVersion > since {
			out = append(out, event)
		}
	}
	return out, nil
}

type fakeServiceCredentials struct {
	tenantRef string
	clientRef string
}

func (f fakeServiceCredentials) VerifyServiceCredential(_ context.Context, clientID, secret string) (trust.ServiceIdentity, error) {
	if clientID != f.clientRef || secret != "s3cr3t" {
		return trust.ServiceIdentity{}, errors.New("bad service credential")
	}
	return trust.ServiceIdentity{TenantRef: f.tenantRef, ClientRef: f.clientRef, ReleaseRef: "rel-1"}, nil
}

// orgEventsTestServer wires the handler behind the real trust middleware: the
// tenant a caller receives must come from the verified credential, never from
// the request, so the test must not be able to fake the context directly.
func orgEventsTestServer(t *testing.T, source OrgEventSource) http.Handler {
	t.Helper()
	handler, err := newOrgEventsHandler(orgEventsTenant, source)
	if err != nil {
		t.Fatalf("new org events handler: %v", err)
	}
	mux := http.NewServeMux()
	handler.register(mux)
	resolver, err := trust.NewResolver(trust.ResolverConfig{
		TenantRef: orgEventsTenant,
		Services:  fakeServiceCredentials{tenantRef: orgEventsTenant, clientRef: "agentatlas"},
		Protected: func(r *http.Request) bool { return r.URL.Path == "/v1/org-events" },
	})
	if err != nil {
		t.Fatalf("new trust resolver: %v", err)
	}
	return resolver.Middleware(mux)
}

func orgEventsRequest(t *testing.T, query string, auth bool) *http.Request {
	t.Helper()
	target := "/v1/org-events"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set(trust.OriginHeader, "agentatlas")
	if auth {
		req.SetBasicAuth("agentatlas", "s3cr3t")
	}
	return req
}

func TestOrgEventsRequiresVerifiedServiceCredential(t *testing.T) {
	source := &fakeOrgEventSource{latest: 3}
	server := orgEventsTestServer(t, source)

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, orgEventsRequest(t, "", false))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated subscribe status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if source.callCount != 0 {
		t.Fatal("an unauthenticated request must never reach the org event source")
	}
}

func TestOrgEventsDerivesTenantFromCredentialNotQuery(t *testing.T) {
	source := &fakeOrgEventSource{latest: 2, events: []OrgEventRecord{
		{EventID: "evt-1", EventType: "org.unit.upserted", OrgVersion: 1, OccurredAt: time.Unix(1, 0).UTC()},
		{EventID: "evt-2", EventType: "org.membership.added", OrgVersion: 2, OccurredAt: time.Unix(2, 0).UTC()},
	}}
	server := orgEventsTestServer(t, source)

	recorder := httptest.NewRecorder()
	// A caller that tries to widen its scope by naming another tenant must be
	// ignored, not obeyed.
	server.ServeHTTP(recorder, orgEventsRequest(t, "enterprise_id=ent-someone-else", true))
	if recorder.Code != http.StatusOK {
		t.Fatalf("subscribe status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if source.gotTenant != orgEventsTenant {
		t.Fatalf("source queried tenant=%q; must be the credential-derived %q", source.gotTenant, orgEventsTenant)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("content-type=%q", contentType)
	}
	body := recorder.Body.String()
	for _, want := range []string{"evt-1", "evt-2", "org.unit.upserted"} {
		if !strings.Contains(body, want) {
			t.Fatalf("stream missing %q; body=%s", want, body)
		}
	}
	// The feed is a change notification, never an evidence channel.
	for _, banned := range []string{"payload", "source_hash"} {
		if strings.Contains(body, banned) {
			t.Fatalf("stream leaked %q; body=%s", banned, body)
		}
	}
}

func TestOrgEventsResumesStrictlyAfterCursor(t *testing.T) {
	source := &fakeOrgEventSource{latest: 3, events: []OrgEventRecord{
		{EventID: "evt-1", EventType: "org.unit.upserted", OrgVersion: 1, OccurredAt: time.Unix(1, 0).UTC()},
		{EventID: "evt-2", EventType: "org.membership.added", OrgVersion: 2, OccurredAt: time.Unix(2, 0).UTC()},
		{EventID: "evt-3", EventType: "org.unit.upserted", OrgVersion: 3, OccurredAt: time.Unix(3, 0).UTC()},
	}}
	server := orgEventsTestServer(t, source)

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, orgEventsRequest(t, "since_version=2", true))
	if recorder.Code != http.StatusOK {
		t.Fatalf("resume status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if source.gotSince != 2 {
		t.Fatalf("source cursor=%d want 2", source.gotSince)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "evt-2") {
		t.Fatalf("resume must be STRICTLY after the cursor; body=%s", body)
	}
	if !strings.Contains(body, "evt-3") {
		t.Fatalf("resume dropped the event after the cursor; body=%s", body)
	}
}

func TestOrgEventsRejectsCursorAheadOfSealedVersion(t *testing.T) {
	source := &fakeOrgEventSource{latest: 2}
	server := orgEventsTestServer(t, source)

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, orgEventsRequest(t, "since_version=9", true))
	// A cursor ahead of the tenant's sealed version means the consumer's state
	// is corrupt: fail loudly rather than hand back a silent empty stream.
	if recorder.Code != http.StatusConflict {
		t.Fatalf("ahead-of-sealed cursor status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestOrgEventsRejectsMalformedCursor(t *testing.T) {
	for _, cursor := range []string{"since_version=-1", "since_version=abc", "since_version=1&since_version=2"} {
		source := &fakeOrgEventSource{latest: 5}
		server := orgEventsTestServer(t, source)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, orgEventsRequest(t, cursor, true))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("cursor %q status=%d want 400", cursor, recorder.Code)
		}
	}
}

func TestOrgEventsFailsClosedWhenSourceUnavailable(t *testing.T) {
	source := &fakeOrgEventSource{latestErr: errors.New("database down")}
	server := orgEventsTestServer(t, source)

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, orgEventsRequest(t, "", true))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("source outage status=%d want 503", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "database down") {
		t.Fatal("internal fault detail must not reach the caller")
	}
}
