package gatewayagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// probeTimeout bounds one readiness probe.
//
// The turn as a whole is already bounded by the policy, but a single
// unresponsive peer must not be allowed to spend that entire budget: the
// operator asked about every service, and a report that names one dead peer and
// silently omits the rest is worse than no report.
const probeTimeout = 5 * time.Second

// maxProbeBodyBytes bounds how much of a readiness response is drained.
const maxProbeBodyBytes = 8 << 10

// Doer is the subset of *http.Client the probe needs.
//
// It is an interface because production dials peers over the mTLS profile
// (transportsecurity.HTTPClient), which pins a server name per peer and swaps
// its transport on every material rotation, while dev dials plaintext.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// HealthTarget is one service whose readiness the assistant may report.
type HealthTarget struct {
	// Name is what an operator calls the service, e.g. "gateway-api".
	Name string
	// ReadinessURL is that service's readiness endpoint.
	ReadinessURL string
	// Client dials this target, and is required.
	//
	// It is per-target rather than shared because an mTLS dial pins the
	// target's server name, so each peer needs its own client. There is
	// deliberately no default: falling back to a plain client would silently
	// dial a production peer in plaintext.
	Client Doer
}

// Fixed reason vocabulary.
//
// A probe reason is NEVER built from anything the peer said. A readiness body
// is attacker-influenceable in exactly the way this package's threat model
// names - it is remote text that would otherwise be handed to the model inside
// a tool result, where it arrives with more authority than the model's own
// output. Reasons are therefore chosen from this list, or formatted from an
// integer status code, and nothing else crosses over.
const (
	reasonUnreachable  = "the service could not be reached"
	reasonTimedOut     = "the service did not answer within the readiness timeout"
	reasonNotReady     = "the service answered and reported itself not ready"
	reasonUnprobeable  = "this service's readiness endpoint is not a usable address"
	reasonStatusFormat = "the service answered with an unexpected status (%d)"
)

// ErrUnknownErrorCode is returned for a code this deployment does not emit.
var ErrUnknownErrorCode = errors.New("gateway agent: that error code is not one this deployment emits")

// errorCatalog decodes the gateway's fixed public failure envelopes.
//
// These are exactly the opaque codes an operator can see, and each one is
// emitted by real code in internal/app. The catalog is deliberately closed: a
// code that is not here produces a refusal, not a plausible-sounding guess,
// because an invented cause is how an operator gets sent to debug the wrong
// system.
var errorCatalog = map[string]ErrorExplanation{
	"invalid_request": {
		Code:     "invalid_request",
		Meaning:  "The gateway rejected the request before acting on it. The body was malformed, carried a field the contract does not define, or carried an identity field that only the verified session is allowed to set.",
		NextStep: "Check the request body against the published contract. Identity fields are never sent by the caller - the gateway derives them from the session.",
	},
	"unsupported_media_type": {
		Code:     "unsupported_media_type",
		Meaning:  "The request did not arrive as application/json, so the gateway did not attempt to decode it.",
		NextStep: "Set the Content-Type header to application/json and send the request again.",
	},
	"request_failed": {
		Code:     "request_failed",
		Meaning:  "The gateway accepted the request but could not complete it. The envelope is intentionally opaque, so the code itself does not narrow the cause.",
		NextStep: "Find the request_id from the same call in the gateway logs and audit record; the specific cause is recorded there, not returned to the caller.",
	},
	"temporarily_unavailable": {
		Code:     "temporarily_unavailable",
		Meaning:  "The token endpoint could not reach something it depends on. This is a retryable condition, not a rejection of the credential.",
		NextStep: "Retry the token request. If it persists, check the readiness of the gateway's dependencies before looking at the client.",
	},
	"invalid_client": {
		Code:     "invalid_client",
		Meaning:  "The client presenting the credential is not a registered client of this deployment, or its credential did not verify.",
		NextStep: "Confirm the client is registered in this environment and that it is using that environment's credential.",
	},
	"invalid_grant": {
		Code:     "invalid_grant",
		Meaning:  "The authorization code or refresh token was expired, already redeemed, or was not issued to the client presenting it.",
		NextStep: "Start the authorization flow again to obtain a fresh grant. A code may only be redeemed once.",
	},
	"unsupported_grant_type": {
		Code:     "unsupported_grant_type",
		Meaning:  "The token request asked for a grant type this deployment does not implement.",
		NextStep: "Check which grant types this deployment's token endpoint advertises and use one of those.",
	},
}

// ServiceDiagnostics is the deterministic backing for the assistant's facts.
//
// Every fact it returns is either a probe outcome or a catalog entry authored
// in this file. Nothing here consults a model, and nothing here passes remote
// text through: that is the whole reason the assistant is allowed to explain
// anything at all.
type ServiceDiagnostics struct {
	targets []HealthTarget
}

var _ DiagnosticsService = (*ServiceDiagnostics)(nil)

// NewServiceDiagnostics builds the diagnostics service over a fixed target set.
//
// An empty target set is refused rather than accepted. An empty HealthReport
// reads to an operator as "nothing is wrong", which is the one answer a health
// check must never give by accident; refusing here means the process reports
// itself not ready and says why, instead of serving a confident blank.
func NewServiceDiagnostics(targets []HealthTarget) (*ServiceDiagnostics, error) {
	if len(targets) == 0 {
		return nil, errors.New("gateway agent: at least one health target is required; an empty health report would read as healthy")
	}
	// The slice is copied so a caller cannot change what the assistant reports
	// after construction.
	copied := make([]HealthTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		name := strings.TrimSpace(target.Name)
		url := strings.TrimSpace(target.ReadinessURL)
		if name == "" || url == "" {
			return nil, errors.New("gateway agent: every health target needs a name and a readiness URL")
		}
		if target.Client == nil {
			return nil, fmt.Errorf("gateway agent: health target %q has no client; there is no default, because defaulting one would dial a peer in plaintext", name)
		}
		if _, duplicate := seen[name]; duplicate {
			// Two components with one name produce a report an operator
			// cannot act on: they cannot tell which one is unhealthy.
			return nil, fmt.Errorf("gateway agent: duplicate health target %q", name)
		}
		seen[name] = struct{}{}
		copied = append(copied, HealthTarget{Name: name, ReadinessURL: url, Client: target.Client})
	}
	return &ServiceDiagnostics{targets: copied}, nil
}

// InspectHealth probes every target and reports what each one answered.
//
// Targets are probed in their configured order so two runs of the same question
// produce the same report; an operator comparing two answers should be reading
// a change in the system, not a change in map iteration order.
func (d *ServiceDiagnostics) InspectHealth(ctx context.Context) (HealthReport, error) {
	if d == nil {
		return HealthReport{}, errors.New("gateway agent: diagnostics service unavailable")
	}
	// The tenant gate is repeated here rather than left to the tool handler:
	// this type is reachable without going through one, and a diagnostics call
	// on nobody's behalf must fail wherever it is made from.
	if _, err := TenantFrom(ctx); err != nil {
		return HealthReport{}, err
	}
	report := HealthReport{Components: make([]ComponentHealth, 0, len(d.targets))}
	for _, target := range d.targets {
		report.Components = append(report.Components, probe(ctx, target))
	}
	return report, nil
}

// probe reports one target's readiness. It never returns an error: a peer that
// is down is a fact about the deployment, which is exactly what was asked for,
// not a failure of the question.
func probe(ctx context.Context, target HealthTarget) ComponentHealth {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.ReadinessURL, nil)
	if err != nil {
		return ComponentHealth{Name: target.Name, Reason: reasonUnprobeable}
	}
	resp, err := target.Client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ComponentHealth{Name: target.Name, Reason: reasonTimedOut}
		}
		// The transport error is not carried into the reason: it is remote-
		// influenced text on its way to a model, and it can name internal
		// addresses that have no business in an assistant's answer.
		return ComponentHealth{Name: target.Name, Reason: reasonUnreachable}
	}
	defer resp.Body.Close()
	// Drained, bounded, and discarded. Draining keeps the connection reusable;
	// the bound stops a hostile peer streaming without end; discarding is the
	// point - the readiness body never reaches the report.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBodyBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return ComponentHealth{Name: target.Name, Ready: true}
	case resp.StatusCode == http.StatusServiceUnavailable:
		// The service's own considered answer about itself: it is up, and it
		// says it is not ready.
		return ComponentHealth{Name: target.Name, Reason: reasonNotReady}
	default:
		// Anything else answered, but not as a readiness endpoint. Naming the
		// status keeps that distinguishable from a service that is simply
		// down, and an integer cannot carry injected text.
		return ComponentHealth{Name: target.Name, Reason: fmt.Sprintf(reasonStatusFormat, resp.StatusCode)}
	}
}

// ExplainError decodes one recorded failure code.
//
// An unrecognized code is refused. The refusal deliberately does not echo the
// code back: the code arrives as a model-chosen tool argument, and echoing it
// into a tool result would let text the model was induced to emit return to it
// wearing the authority of a deterministic answer.
func (d *ServiceDiagnostics) ExplainError(ctx context.Context, code string) (ErrorExplanation, error) {
	if d == nil {
		return ErrorExplanation{}, errors.New("gateway agent: diagnostics service unavailable")
	}
	if _, err := TenantFrom(ctx); err != nil {
		return ErrorExplanation{}, err
	}
	explanation, ok := errorCatalog[strings.ToLower(strings.TrimSpace(code))]
	if !ok {
		return ErrorExplanation{}, ErrUnknownErrorCode
	}
	return explanation, nil
}
