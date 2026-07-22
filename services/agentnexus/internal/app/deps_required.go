package app

import "github.com/astraclawteam/agentnexus/services/agentnexus/internal/wiring"

// optionalGatewayConfig names every inspectable PostgresGatewayConfig field a
// deployment may legitimately leave unset, each with the reason it is allowed.
// Everything else is required of cmd/gateway-api.
//
// This is the outer half of the gateway's wiring guard: the config is what the
// binary hands over, so it is where a NEW port arrives. Both current entries are
// genuinely deployment-gated, which means MissingRequired over this struct
// reports nothing today. Its value is entirely in
// TestOptionalGatewayConfigIsExact: the next port added here - the evidence
// runtime's object/key/content ports among them - cannot be added without
// someone deciding, in writing, whether the binary must supply it.
var optionalGatewayConfig = map[string]string{
	"ApprovalChannel": "deployment-gated. Unset leaves the approval transmission endpoints UNREGISTERED - " +
		"fail closed, no resolution fallback, because AgentNexus never chooses approvers (GA Task 0E). " +
		"cmd/gateway-api supplies a pending-delivery channel when AGENTNEXUS_APPROVAL_CHANNEL is set.",
	"DispatchPublisher": "deployment-gated. Without a message bus the transactional outbox still commits " +
		"every dispatch intent and the recovery pump stays nil; Actions reach `dispatched` and stop there. " +
		"A CONFIGURED bus that cannot be reached is a startup failure in cmd/gateway-api, not this.",
}

// optionalGatewayDeps names every inspectable BrowserAuthDependencies field the
// PRODUCTION gateway composition may legitimately leave nil.
//
// The bar here is deliberately higher than newBrowserAuthHandler's own nil
// check. That constructor serves in-memory tests and reduced routers too, so it
// only refuses when the handler could not function at all; every optional
// surface is free to be absent and simply goes unregistered. For the shipped
// gateway-api binary an absent surface is not a configuration, it is a missing
// product: a caller gets a bare 404 that says nothing about why. So each field
// left out of production is listed here and has to say why.
//
// Evidence WAS the live instance of the defect this guard exists for:
// implemented, unit-tested, covered by evidence_handler_test.go, and constructed
// by nothing. Task B6 gave it a constructor (buildEvidenceRuntime), so its entry
// below is now a deployment gate like ApprovalTransmission's rather than an
// admission that nobody built it.
var optionalGatewayDeps = map[string]string{
	"TokenIssuer": "defaults to browserauth.NewTokenIssuer(deps.Config) inside newBrowserAuthHandler when unset; " +
		"the production composition takes that default deliberately rather than duplicating the construction.",
	"ApprovalTransmission": "constructed only when PostgresGatewayConfig.ApprovalChannel is supplied; see " +
		"optionalGatewayConfig for why the channel itself is deployment-gated.",
	"Evidence": "deployment-gated (task B6 wired it). buildEvidenceRuntime constructs the semantic evidence " +
		"runtime — and with it the Task 0F ActionBindingVerifier — when EvidenceObjectRoot, " +
		"EvidenceContentKeyRef and EvidenceContentKey are all supplied; a PARTIAL set is a startup error " +
		"there, not a silent skip. Unset, /v1/runtime/locate and /v1/runtime/read stay unregistered, which " +
		"is the historical shape and the only safe default: the content key must be operator-supplied and " +
		"STABLE (reads resolve a handle's key by the ref persisted at locate time, so a generated " +
		"per-process key would orphan every handle across a restart). Registering the surface does not make " +
		"it serve data: the source binding registry has no registration path yet, so every locate denies " +
		"with not_resolvable, and the content source is PendingContentSource. Both are task B3.",
}

// The three evidence config fields deliberately do NOT appear in
// optionalGatewayConfig. They are a string, a string and a []byte — value kinds
// wiring.Inspects skips on purpose — so listing them would fail
// TestOptionalGatewayConfigIsExact for excluding nothing. Their all-or-nothing
// requirement is encoded explicitly in buildEvidenceRuntime instead, which is
// the escape hatch wiring/required.go documents for exactly this case.

// MissingRequired reports the inspectable dependencies this config leaves nil,
// sorted, excluding the deployment-gated ones declared in optionalGatewayConfig.
func (c PostgresGatewayConfig) MissingRequired() []string {
	return wiring.MissingRequired(c, optionalGatewayConfig)
}

// MissingRequired reports the inspectable dependencies this dependency set
// leaves nil, sorted, excluding those declared in optionalGatewayDeps.
//
// An empty result means the production gateway composed every surface it is
// contracted to serve. It does not mean any of them answers correctly.
func (d BrowserAuthDependencies) MissingRequired() []string {
	return wiring.MissingRequired(d, optionalGatewayDeps)
}
