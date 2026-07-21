// Package gatewayagent is the bounded operations assistant of the AgentNexus
// gateway.
//
// Its job is to help an operator understand and prepare: inspect health,
// explain an error, prepare a connector onboarding, validate a draft package or
// binding, propose diagnostics. Its job is emphatically NOT to decide anything
// that belongs to the trusted execution plane. Risk verdicts, approver choice,
// grant issuance, Action execution, policy changes, package installation and
// Secret values all stay outside it, and the assistant is not the component
// that gets to be persuaded otherwise.
//
// That boundary is enforced here as data and a default-deny check rather than
// as prose in a prompt: a model can be talked out of an instruction, and the
// eval set for this component includes prompt injection arriving through
// connector metadata. It cannot be talked out of a lookup that fails closed.
package gatewayagent

import (
	"errors"
	"fmt"
	"time"
)

// ToolCapability names one thing a tool is permitted to do.
type ToolCapability string

const (
	// CapabilityInspectHealth reads deterministic service health.
	CapabilityInspectHealth ToolCapability = "inspect_health"
	// CapabilityExplainError turns a recorded failure into operator language.
	CapabilityExplainError ToolCapability = "explain_error"
	// CapabilityPrepareConnectorOnboarding drafts connector onboarding steps.
	CapabilityPrepareConnectorOnboarding ToolCapability = "prepare_connector_onboarding"
	// CapabilityValidateDraft validates a package or binding DRAFT. Validating
	// is not installing: the draft still requires human confirmation.
	CapabilityValidateDraft ToolCapability = "validate_draft"
	// CapabilityProposeDiagnostics proposes next diagnostic steps.
	CapabilityProposeDiagnostics ToolCapability = "propose_diagnostics"
)

// AllowedCapabilities is the complete allow-list. Adding an entry is a
// deliberate widening of what the assistant may reach, and the policy test
// pins the length so it cannot happen by accident.
var AllowedCapabilities = []ToolCapability{
	CapabilityInspectHealth,
	CapabilityExplainError,
	CapabilityPrepareConnectorOnboarding,
	CapabilityValidateDraft,
	CapabilityProposeDiagnostics,
}

// ForbiddenIntents are named refusals. Default-deny already covers them, so
// this list is redundant by construction - and that is the point: it keeps the
// refusals greppable, reviewable, and resilient to a careless allow-list edit
// that would otherwise silently grant one of them.
var ForbiddenIntents = []ToolCapability{
	"decide_domain_risk",
	"choose_approvers",
	"issue_grant",
	"execute_action",
	"read_business_data",
	"change_policy",
	"install_package",
	"read_secret",
}

// ErrCapabilityDenied is returned for anything not on the allow-list.
var ErrCapabilityDenied = errors.New("tool capability denied")

// Default bounds for one assistant turn.
//
// These are not performance tuning. An assistant with unbounded tool calls can
// be driven into a loop by hostile connector metadata; unbounded output can be
// used to flood an operator or a log; an unbounded turn holds a session open
// indefinitely. Each cap turns a class of abuse into a boring, visible refusal.
const (
	defaultMaxToolCalls  = 8
	defaultMaxOutputByte = 16 << 10
	defaultTurnTimeout   = 60 * time.Second
)

// Policy is the immutable capability and bounds decision for the assistant.
type Policy struct {
	allowed        map[ToolCapability]struct{}
	maxToolCalls   int
	maxOutputBytes int
	timeout        time.Duration
}

// NewPolicy builds the capability policy. The allow-list is copied so a caller
// cannot widen a live policy by mutating the package variable.
func NewPolicy() Policy {
	allowed := make(map[ToolCapability]struct{}, len(AllowedCapabilities))
	for _, capability := range AllowedCapabilities {
		allowed[capability] = struct{}{}
	}
	policy := Policy{
		allowed:        allowed,
		maxToolCalls:   defaultMaxToolCalls,
		maxOutputBytes: defaultMaxOutputByte,
		timeout:        defaultTurnTimeout,
	}
	return policy
}

// Allow reports whether the assistant may exercise this capability. Anything
// not explicitly allowed is denied, including the empty capability and any
// near-miss spelling of an allowed one.
func (p Policy) Allow(capability ToolCapability) error {
	if _, ok := p.allowed[capability]; ok {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrCapabilityDenied, capability)
}

// MaxToolCalls bounds tool calls in one turn.
func (p Policy) MaxToolCalls() int { return p.maxToolCalls }

// MaxOutputBytes bounds assistant output in one turn.
func (p Policy) MaxOutputBytes() int { return p.maxOutputBytes }

// Timeout bounds the wall-clock duration of one turn.
func (p Policy) Timeout() time.Duration { return p.timeout }
