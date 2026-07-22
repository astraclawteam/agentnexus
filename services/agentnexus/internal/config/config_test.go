package config

import (
	"slices"
	"strings"
	"testing"
)

// TestParseProbeTargetsRejectsMalformedEntries: a skipped entry produces a
// readiness report that is missing a service without saying so, and a report an
// operator reads as complete when it is not is worse than a startup failure.
func TestParseProbeTargetsRejectsMalformedEntries(t *testing.T) {
	for _, raw := range []string{
		"gateway-api",                        // no url
		"gateway-api=",                       // empty url
		"=http://gateway-api/readyz",         // no name
		"gateway-api=http://a/readyz,worker", // one good, one not
	} {
		if _, err := ParseProbeTargets(raw); err == nil {
			t.Errorf("ParseProbeTargets(%q) accepted a malformed list", raw)
		}
	}
}

// TestParseProbeTargetsKeepsOrder: the health report is emitted in this order,
// and an operator comparing two answers should be reading a change in the
// system rather than a change in ordering.
func TestParseProbeTargetsKeepsOrder(t *testing.T) {
	targets, err := ParseProbeTargets(" gateway-api=http://a/readyz , connector-worker=http://b/readyz ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []ProbeTarget{
		{Name: "gateway-api", URL: "http://a/readyz"},
		{Name: "connector-worker", URL: "http://b/readyz"},
	}
	if !slices.Equal(targets, want) {
		t.Fatalf("parsed %v; want %v", targets, want)
	}
}

// TestParseProbeTargetsEmptyIsNotAnError: an unset variable is a deployment
// that has not configured probing, which the caller decides what to do about.
// It is distinct from a value that is present and wrong.
func TestParseProbeTargetsEmptyIsNotAnError(t *testing.T) {
	targets, err := ParseProbeTargets("")
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("parsed %d targets from an empty value", len(targets))
	}
}

// TestLLMRouterIsAllOrNothing: model access is llmrouter-only with no
// direct-provider fallback, so a half-configured router must not read as
// usable.
func TestLLMRouterIsAllOrNothing(t *testing.T) {
	complete := LLMRouterSettings{BaseURL: "https://router", APIKey: "k", Model: "m"}
	if !complete.Complete() || !complete.Configured() {
		t.Fatal("a fully set router did not report itself complete")
	}
	partial := LLMRouterSettings{BaseURL: "https://router"}
	if partial.Complete() {
		t.Fatal("a router with no key or model reported itself complete")
	}
	if !partial.Configured() {
		t.Fatal("a partially set router reported itself unconfigured, which hides the misconfiguration")
	}
}

// TestLLMRouterMissingNeverCarriesValues is why Missing exists in this shape.
//
// Its result is written into a /readyz body and a log line, and one of the
// three values is a secret. Returning variable NAMES is what makes that safe.
func TestLLMRouterMissingNeverCarriesValues(t *testing.T) {
	const secret = "sk-router-secret-value"
	settings := LLMRouterSettings{BaseURL: "https://router", APIKey: secret}
	missing := settings.Missing()
	if len(missing) != 1 || missing[0] != "AGENTNEXUS_LLMROUTER_MODEL" {
		t.Fatalf("Missing() = %v; want only the unset model variable", missing)
	}
	if strings.Contains(strings.Join(missing, ","), secret) {
		t.Fatal("Missing() carried the API key")
	}
}
