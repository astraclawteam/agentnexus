package app

import (
	"reflect"
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/wiring"
)

// These assertions deliberately do NOT read postgres_gateway.go's source text.
// A test that greps a composition root for a call proves only that a string is
// present; this repo deleted four such tests this week for exactly that, one of
// them a gate on cmd/gateway-api that passed happily while the router it
// "verified" was built by no deployment at all.
//
// What is provable here is the guard's own behaviour: which fields it reports,
// which it excuses, and that the excuse list still describes reality. What is
// NOT provable here is that the shipped binary reaches the call - see the note
// in NewPostgresGatewayRouter.

func TestBrowserAuthDepsMissingRequiredNamesEveryUnwiredSurface(t *testing.T) {
	missing := BrowserAuthDependencies{}.MissingRequired()
	// Every surface the production gateway must construct. Actions and OrgEvents
	// are named explicitly because they are optional to newBrowserAuthHandler -
	// absent, they simply go unregistered - and that difference in bar is the
	// entire reason this guard exists separately from the constructor's check.
	for _, want := range []string{
		"Sessions", "Upstream", "Identities", "Profiles", "Audit", "AuditEvidence",
		"AuthorizeRateLimiter", "AuthorizeSourceResolver", "AuthorizationPolicy",
		"OrgVersions", "TicketActors", "StepGrants", "Grants", "Actions", "OrgEvents",
	} {
		if !contains(missing, want) {
			t.Errorf("an empty dependency set must report %s missing, got %v", want, missing)
		}
	}
}

func TestBrowserAuthDepsExcusesOnlyTheDeclaredOptionalSurfaces(t *testing.T) {
	missing := BrowserAuthDependencies{}.MissingRequired()
	for name := range optionalGatewayDeps {
		if contains(missing, name) {
			t.Errorf("%s is declared optional but was still reported missing", name)
		}
	}
	// Evidence used to be the live instance of the defect class: implemented,
	// unit-tested, constructed by nobody. Task B6 gave it buildEvidenceRuntime,
	// so it is now excused for the same reason ApprovalTransmission is — the
	// deployment must supply a staging root and a stable content key, and there
	// is no safe default for either. The excuse still has to exist IN WRITING,
	// and removing it must still make the guard report Evidence missing;
	// otherwise a future change that drops the constructor goes unnoticed.
	if _, declared := optionalGatewayDeps["Evidence"]; !declared {
		t.Fatal("Evidence is no longer declared optional; then buildEvidenceRuntime must construct it unconditionally")
	}
	if !contains(withoutOptional(t, "Evidence"), "Evidence") {
		t.Error("removing the Evidence excuse does not make the guard report it; the excuse is doing nothing")
	}
}

// Every excuse must be load-bearing. An entry that names a field the guard
// would not have reported anyway is doing nothing, and a reader who finds it
// there will believe a decision was made that was not. This generalises the
// Evidence check above to the whole set, so an excuse cannot rot into decoration
// without the suite noticing.
func TestEveryOptionalGatewayDepsEntryActuallyExcusesSomething(t *testing.T) {
	for name := range optionalGatewayDeps {
		if !contains(withoutOptional(t, name), name) {
			t.Errorf("the %s excuse changes nothing: the guard does not report it even when the entry is removed", name)
		}
	}
}

// No silent third category. Every inspectable field of the production
// dependency set is either reported by MissingRequired or excused in writing -
// never neither, never both. This is the property that makes the two lists a
// partition of the dependency contract rather than two overlapping opinions
// about it.
//
// Note what is NOT asserted: that MissingRequired returns empty once every
// surface is set. Go reflection cannot synthesize a value implementing an
// arbitrary interface (there is no MakeInterface to pair with MakeFunc), so
// filling these fields generically is impossible, and hand-writing stubs for
// eighteen production ports would be a fixture that decays faster than the guard
// it covers. That direction is proved instead in internal/wiring, against types
// the test owns, where it is a property of the shared engine every caller runs.
func TestEveryInspectableGatewayDependencyIsEitherReportedOrExcused(t *testing.T) {
	missing := BrowserAuthDependencies{}.MissingRequired()
	typ := reflect.TypeOf(BrowserAuthDependencies{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !field.IsExported() || !wiring.Inspects(field.Type.Kind()) {
			continue
		}
		_, excused := optionalGatewayDeps[field.Name]
		if reported := contains(missing, field.Name); reported == excused {
			t.Errorf("%s is reported=%t and excused=%t; every dependency must be exactly one of the two", field.Name, reported, excused)
		}
	}
}

func TestPostgresGatewayConfigMissingRequiredIsEmptyWhileEveryPortIsDeploymentGated(t *testing.T) {
	// Both current ports are legitimately deployment-gated, so this reports
	// nothing today. That is the honest state, not a passing check: the value of
	// the config-side guard is TestOptionalGatewayConfigIsExact forcing a
	// decision on the next port added to PostgresGatewayConfig.
	if missing := (PostgresGatewayConfig{}).MissingRequired(); len(missing) > 0 {
		t.Fatalf("MissingRequired() = %v, want none while every config port is deployment-gated", missing)
	}
}

// TestOptionalGatewayDepsIsExact and its config sibling are what make this
// maintainable rather than another list to forget. Every excused name must be a
// real field the guard actually inspects, carrying a stated reason. A stale
// entry silently downgrades a required dependency to optional, which is
// precisely how a wiring gap comes back. In AgentAtlas this same assertion
// immediately caught three entries naming concrete pointers - a kind that
// reflection never looked at - so those excuses had been meaningless from the
// day they were written.
func TestOptionalGatewayDepsIsExact(t *testing.T) {
	if stale := wiring.StaleOptional(BrowserAuthDependencies{}, optionalGatewayDeps); len(stale) > 0 {
		t.Fatalf("optionalGatewayDeps has stale entries: %s", strings.Join(stale, "; "))
	}
}

func TestOptionalGatewayConfigIsExact(t *testing.T) {
	if stale := wiring.StaleOptional(PostgresGatewayConfig{}, optionalGatewayConfig); len(stale) > 0 {
		t.Fatalf("optionalGatewayConfig has stale entries: %s", strings.Join(stale, "; "))
	}
}

// withoutOptional recomputes the missing set with one excuse removed, so a test
// can prove an entry is load-bearing instead of assuming it.
func withoutOptional(t *testing.T, drop string) []string {
	t.Helper()
	reduced := make(map[string]string, len(optionalGatewayDeps))
	for name, reason := range optionalGatewayDeps {
		if name != drop {
			reduced[name] = reason
		}
	}
	return wiring.MissingRequired(BrowserAuthDependencies{}, reduced)
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
