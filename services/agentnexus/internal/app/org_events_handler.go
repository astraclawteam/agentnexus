package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

// orgEventsPageLimit bounds one catch-up page. The public contract promises a
// resumable stream, not an unbounded one: a consumer that is far behind
// reconnects with the cursor it reached. Keeping the page bounded means a cold
// consumer can never pin an arbitrary amount of server memory.
const orgEventsPageLimit = 500

// OrgEventRecord is one organization change as published on the public feed.
// It deliberately mirrors the OrgEvent contract schema and nothing more: the
// organization payload and the source digest stay inside AgentNexus and are
// reachable only through the evidence surface under an Access Ticket. Widening
// this struct would silently turn the notification feed into a second read
// path around that boundary.
type OrgEventRecord struct {
	EventID    string
	EventType  string
	OrgVersion int64
	OccurredAt time.Time
}

// OrgEventSource is the sealed organization change feed behind
// GET /v1/org-events. Both methods are tenant-scoped by an argument the handler
// takes from the verified credential, never from the request.
type OrgEventSource interface {
	// LatestSealedVersion returns the tenant's current sealed organization
	// version. It exists so a cursor ahead of reality fails loudly.
	LatestSealedVersion(ctx context.Context, tenantRef string) (int64, error)
	// EventsSince returns sealed changes STRICTLY after sinceVersion, oldest
	// first, at most limit of them.
	EventsSince(ctx context.Context, tenantRef string, sinceVersion int64, limit int) ([]OrgEventRecord, error)
}

// orgEventsHandler serves the organization change feed. Identity, and
// therefore tenant scope, derives from the ingress-resolved trusted context
// only; the operation declares no tenant parameter, so a caller cannot widen
// its own scope.
type orgEventsHandler struct {
	enterpriseID string
	source       OrgEventSource
}

func newOrgEventsHandler(enterpriseID string, source OrgEventSource) (*orgEventsHandler, error) {
	if enterpriseID == "" || source == nil {
		return nil, errors.New("org events dependencies incomplete")
	}
	return &orgEventsHandler{enterpriseID: enterpriseID, source: source}, nil
}

func (h *orgEventsHandler) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/org-events", h.subscribe)
}

func (h *orgEventsHandler) subscribe(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	trustedCtx, err := trust.FromRequest(r)
	if err != nil {
		if trust.HTTPStatus(err) == http.StatusServiceUnavailable {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "trust_unavailable"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_service"})
		return
	}
	// The feed is a first-party service surface: browser and ticket credentials
	// never subscribe to the organization graph wholesale.
	if trustedCtx.Source != trust.SourceServiceCredential || trustedCtx.Principal.TenantRef != h.enterpriseID {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_service"})
		return
	}

	sinceVersion, ok := parseSinceVersion(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_since_version"})
		return
	}

	tenantRef := trustedCtx.Principal.TenantRef
	latest, err := h.source.LatestSealedVersion(r.Context(), tenantRef)
	if err != nil {
		// A persistence outage is retryable-unavailable and the cause never
		// reaches the caller.
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "org_events_unavailable"})
		return
	}
	if sinceVersion > latest {
		// The consumer claims to have applied a version this tenant has never
		// sealed: its state is corrupt. Failing loudly beats a silent empty
		// stream that looks like "nothing changed".
		writeJSON(w, http.StatusConflict, map[string]string{"error": "cursor_ahead_of_sealed_version"})
		return
	}

	events, err := h.source.EventsSince(r.Context(), tenantRef, sinceVersion, orgEventsPageLimit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "org_events_unavailable"})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	for _, event := range events {
		payload, err := json.Marshal(map[string]any{
			"event_id":    event.EventID,
			"event_type":  event.EventType,
			"org_version": event.OrgVersion,
			"occurred_at": event.OccurredAt.UTC().Format(time.RFC3339Nano),
		})
		if err != nil {
			// The stream is already committed, so there is no status code left
			// to change: stop rather than emit a malformed frame.
			return
		}
		// The SSE id is the sealed version, so a reconnecting consumer resumes
		// from Last-Event-ID without inventing its own bookkeeping.
		if _, err := fmt.Fprintf(w, "id: %d\nevent: org\ndata: %s\n\n", event.OrgVersion, payload); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// parseSinceVersion reads the resumable cursor. Absent means "from the first
// retained event". A repeated, non-numeric or negative cursor is a client bug
// and is refused rather than coerced.
func parseSinceVersion(r *http.Request) (int64, bool) {
	values := r.URL.Query()["since_version"]
	if len(values) == 0 {
		return 0, true
	}
	if len(values) > 1 {
		return 0, false
	}
	parsed, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || parsed < 0 {
		return 0, false
	}
	return parsed, true
}
