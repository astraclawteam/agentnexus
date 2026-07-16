package runtime

// http_openapi.go is the generic HTTP/OpenAPI read connector family, qualified
// to the GA Product Pack v1 contract. It executes over an INJECTED HTTP client
// port (a bounded RoundTripper facade) so the conformance suite drives it with
// deterministic fakes. It covers: pagination (follow the next-page token until
// exhausted, aggregating), rate limiting (HTTP 429 -> honor Retry-After with
// bounded retries), ACL/deletion invalidation (403/404 -> fail closed, no stale
// data), output-schema validation and field masking, deadline -> bounded
// failure, and authoritative source/version/freshness read metadata. It never
// receives a master credential (the host adapter redeems the handle for derived
// material) and never leaks connector topology into its output.

import (
	"context"
	"errors"
	"time"
)

// maxPages and maxRateRetries bound one read so a hostile or misconfigured
// upstream can never make the family loop or retry unbounded.
const (
	maxPages        = 1000
	maxRateRetries  = 3
	maxRetryBackoff = 2 * time.Second
)

// HTTPFetch is one bounded page request to the injected HTTP client. The auth is
// DERIVED material (never a master credential); the resource/operation are
// server-side resolved coordinates.
type HTTPFetch struct {
	Resource  string
	Operation string
	PageToken string
	Auth      string
}

// HTTPPage is one page the injected HTTP client returns. StatusCode carries the
// upstream HTTP status so the family can honor 429/403/404; NextPageToken drives
// pagination; the source/version/authority fields carry the authoritative read
// metadata (business-semantic, never connector topology).
type HTTPPage struct {
	StatusCode    int
	RetryAfter    time.Duration
	NextPageToken string
	Records       []map[string]any
	Source        string
	SourceVersion int64
	Authority     string
}

// HTTPClient is the injected outbound HTTP port. A production connector wires a
// real RoundTripper-backed client; the conformance suite wires a deterministic
// fake. The family owns pagination/retry/schema/masking; the client owns one
// bounded round trip.
type HTTPClient interface {
	Fetch(ctx context.Context, req HTTPFetch) (HTTPPage, error)
}

// HTTPOpenAPIAdapter is the http/openapi read family adapter.
type HTTPOpenAPIAdapter struct {
	client HTTPClient
	sleep  func(ctx context.Context, d time.Duration) error
	now    func() time.Time
}

// NewHTTPOpenAPIAdapter binds the family to its injected HTTP client.
func NewHTTPOpenAPIAdapter(client HTTPClient) *HTTPOpenAPIAdapter {
	return &HTTPOpenAPIAdapter{client: client, sleep: sleepCtx, now: func() time.Time { return time.Unix(0, 0).UTC() }}
}

// Name identifies the family for audit.
func (*HTTPOpenAPIAdapter) Name() string { return "http_openapi" }

// Execute runs one paginated, rate-limited, ACL-checked, masked and
// schema-validated read over the injected HTTP client, surfacing the
// authoritative source/version/freshness metadata. It maps an upstream 429 to a
// bounded Retry-After retry, a 403/404 to a fail-closed denial, and a deadline
// or transport error to a bounded failure.
func (a *HTTPOpenAPIAdapter) Execute(ctx context.Context, req FamilyRequest) (FamilyResponse, error) {
	fetch := func(ctx context.Context, token string) (pageData, error) {
		page, err := a.client.Fetch(ctx, HTTPFetch{Resource: req.Resource, Operation: req.Operation, PageToken: token, Auth: req.Auth})
		if err != nil {
			return pageData{}, err
		}
		d := pageData{
			records:       toRecords(page.Records),
			next:          page.NextPageToken,
			source:        page.Source,
			sourceVersion: page.SourceVersion,
			authority:     page.Authority,
		}
		switch {
		case page.StatusCode == 429:
			d.rateLimited = true
			d.retryAfter = page.RetryAfter
		case page.StatusCode == 403 || page.StatusCode == 404:
			d.denied = true
		case page.StatusCode != 200:
			d.failed = true
			d.failReason = "unexpected upstream status"
		}
		return d, nil
	}
	return runReadPipeline(ctx, fetch, req.FieldPolicy, a.sleep, a.now)
}

// sleepCtx sleeps for d or until ctx is done, returning ctx.Err() if cancelled.
// It is the family's bounded, context-aware Retry-After honoring primitive.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	if d > maxRetryBackoff {
		d = maxRetryBackoff
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// isDeadline reports whether err is a context deadline/cancellation the family
// converts to a bounded failure rather than propagating.
func isDeadline(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}
