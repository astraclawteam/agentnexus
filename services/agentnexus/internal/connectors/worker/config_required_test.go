package worker

import (
	"reflect"
	"strings"
	"testing"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/wiring"
)

// These assertions deliberately do NOT read cmd/connector-worker/main.go's
// source text. A test that greps a composition root for a call proves only that
// a string is present; this repo deleted four such tests this week for that,
// and the connector worker in particular already shipped a contradiction those
// gates could never have caught (a startup line printing ready=true while
// /readyz on the same process answered 503).

func TestMissingRequiredNamesEverySeamAndEveryIdentityRef(t *testing.T) {
	missing := Config{}.MissingRequired()
	want := []string{
		"Actions", "Observations", "Resolver", "Signer",
		"Identity.AgentClientRef", "Identity.AgentReleaseRef", "Identity.OrgSnapshotRef", "Identity.PrincipalRef",
	}
	for _, name := range want {
		if !contains(missing, name) {
			t.Errorf("an empty config must report %s missing, got %v", name, missing)
		}
	}
}

// The identity refs are the half a reflection-only guard cannot see. This is the
// assertion that fails if someone "simplifies" MissingRequired down to
// wiring.MissingRequired alone: a Config with every seam wired and a blank
// identity would then report nothing, and the worker would take the stream under
// an unattributable principal.
func TestMissingRequiredStillReportsBlankIdentityRefsWhenEverySeamIsWired(t *testing.T) {
	wired := everySeamWired(t)
	// Exactly what cmd/connector-worker supplies today: its own service name and
	// nothing else, because the other three refs have no configuration surface.
	wired.Identity = Identity{PrincipalRef: "connector-worker"}
	missing := wired.MissingRequired()
	want := []string{"Identity.AgentClientRef", "Identity.AgentReleaseRef", "Identity.OrgSnapshotRef"}
	if !reflect.DeepEqual(missing, want) {
		t.Fatalf("MissingRequired() = %v, want exactly the three identity refs with no config surface: %v", missing, want)
	}
}

// This is the state cmd/connector-worker actually ships in, and it is the reason
// the guard exists for this binary: the failure has to be NAMED rather than
// papered over. Nothing in this repo can satisfy the config yet - the private
// Postgres BindingResolver and the evidence-backed ObservationProducer land with
// task B3, and three identity refs have no configuration surface at all - so a
// guard that could ever return empty here would be lying.
func TestTheShippedWorkerConfigCannotYetBeSatisfied(t *testing.T) {
	shipped := Config{Identity: Identity{PrincipalRef: "connector-worker"}}
	missing := shipped.MissingRequired()
	if len(missing) == 0 {
		t.Fatal("the shipped config reports nothing missing; task B3 either landed or the guard stopped looking")
	}
	if _, err := New(shipped); err == nil {
		t.Fatal("worker.New accepted a config the guard says is incomplete")
	}
}

func TestMissingRequiredIsEmptyOnceEverySeamAndRefIsSupplied(t *testing.T) {
	complete := everySeamWired(t)
	complete.Identity = workerIdentity()
	if missing := complete.MissingRequired(); len(missing) > 0 {
		t.Fatalf("MissingRequired() = %v, want none", missing)
	}
	// The guard and the constructor must agree on a complete config. If they
	// diverge, one of them is describing a contract the other does not hold.
	if _, err := New(complete); err != nil {
		t.Fatalf("worker.New refused a config the guard calls complete: %v", err)
	}
}

// TestOptionalWorkerDepsIsExact is what makes the excuse list maintainable
// rather than another list to forget: every excused name must be a real,
// inspectable field carrying a stated reason. Adding a seam to Config then
// forces a decision - wire it in cmd/connector-worker, or declare it here and
// say why.
func TestOptionalWorkerDepsIsExact(t *testing.T) {
	if stale := wiring.StaleOptional(Config{}, optionalWorkerDeps); len(stale) > 0 {
		t.Fatalf("optionalWorkerDeps has stale entries: %s", strings.Join(stale, "; "))
	}
}

// The identity list has the same failure mode as the excuse list, one step
// removed: these names are strings compared by reflection, so a renamed field
// would leave the guard silently checking nothing. FieldByName returns a zero
// Value for an unknown name, and calling String() on it yields "<invalid
// Value>" rather than panicking - which would report the field permanently
// present. Nothing but this assertion would notice.
func TestRequiredIdentityFieldsAreRealStringFields(t *testing.T) {
	typ := reflect.TypeOf(Identity{})
	for _, name := range requiredIdentityFields {
		field, exists := typ.FieldByName(name)
		if !exists {
			t.Errorf("requiredIdentityFields names %s, which is not a field of Identity", name)
			continue
		}
		if field.Type.Kind() != reflect.String {
			t.Errorf("%s is %s; the blank check only means anything for a string", name, field.Type.Kind())
		}
	}
	if got, want := len(requiredIdentityFields), typ.NumField(); got != want {
		t.Errorf("requiredIdentityFields covers %d of %d Identity fields; Identity.validate rejects a blank in ANY of them", got, want)
	}
}

// everySeamWired returns a Config with all four execution seams filled by the
// package's existing fakes and NO identity, so each test can state its own
// identity case. It reuses those fakes rather than declaring parallel stubs:
// a second set would be free to drift out of the interfaces the real tests pin.
func everySeamWired(t *testing.T) Config {
	t.Helper()
	signer, key := newReceiptSigner(t)
	service, err := actions.NewService(actions.NewMemoryStore(), actions.NewMemoryAuditSink(),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(sdkaudit.NewKeySet(key))))
	if err != nil {
		t.Fatalf("actions.NewService: %v", err)
	}
	return Config{
		Actions:      service,
		Resolver:     &fakeResolver{},
		Signer:       signer,
		Observations: newFakeObservations(),
	}
}

func contains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}
