package app

import (
	"errors"
	"strings"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/trust"
)

// RequestContext is the typed per-request context propagated internally: the
// immutable credential-derived principal plus public correlation data.
//
// The legacy envelope parser (ParseRequestContext over caller-supplied
// enterprise_id/actor_user_id values) is retired: request envelopes carry
// correlation ONLY, and identity exists exclusively on the verified
// principal resolved at ingress.
type RequestContext struct {
	// Principal is the immutable credential-derived principal context.
	Principal runtime.PrincipalContext
	// Source is the credential kind that produced the principal.
	Source trust.Source
	// OrgVersion is the sealed organization snapshot version pinned at
	// ingress.
	OrgVersion int64
	// RequestID and TraceID are public correlation values from the request
	// envelope. They carry no trust.
	RequestID string
	TraceID   string
}

// ErrUntrustedRequestContext reports an attempt to build a request context
// without a verified principal.
var ErrUntrustedRequestContext = errors.New("request context requires a credential-derived principal")

// NewRequestContext binds envelope correlation to the immutable trusted
// context resolved at ingress. There is deliberately no constructor from
// caller-supplied identity values.
func NewRequestContext(trustedCtx trust.Context, requestID, traceID string) (RequestContext, error) {
	if err := trustedCtx.Principal.Validate(); err != nil {
		return RequestContext{}, errors.Join(ErrUntrustedRequestContext, err)
	}
	if !canonicalCorrelationValue(requestID) || len(requestID) > 128 {
		return RequestContext{}, errors.New("request_id must be canonical and at most 128 bytes")
	}
	if traceID != "" && (!canonicalCorrelationValue(traceID) || len(traceID) > 128) {
		return RequestContext{}, errors.New("trace_id must be canonical and at most 128 bytes")
	}
	return RequestContext{
		Principal:  trustedCtx.Principal,
		Source:     trustedCtx.Source,
		OrgVersion: trustedCtx.OrgVersion,
		RequestID:  requestID,
		TraceID:    traceID,
	}, nil
}

func canonicalCorrelationValue(value string) bool {
	return value != "" && strings.TrimSpace(value) == value
}
