package worker

import (
	"reflect"
	"sort"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/wiring"
)

// optionalWorkerDeps names every inspectable Config field a composition root may
// legitimately leave nil, with the reason. Everything else is required of
// cmd/connector-worker.
//
// Only one entry, and it records a divergence rather than a design: Config's own
// doc calls the Secret Provider a readiness probe and CheckReady says a missing
// or unreachable provider is a hard not-ready, but the code it describes only
// probes when one is set, so a worker composed without a provider passes that
// gate. The guard reports what the code does, not what the comment claims; a
// guard that quietly asserted the stricter reading would make the binary refuse
// for a reason no reader could find. Closing the gap is a change to CheckReady,
// and when it lands this entry comes out.
var optionalWorkerDeps = map[string]string{
	"Secrets": "CheckReady only probes a Secret Provider when one is set, so a worker composed without one " +
		"still passes readiness today. See the note above optionalWorkerDeps.",
}

// requiredIdentityFields names the Identity fields that must carry a value.
//
// This is the deliberate encoding wiring.Inspects refuses to guess at. Identity
// is a struct of four strings, and reflection over nilable kinds cannot see a
// string at all: it would skip Identity entirely and report a fully wired
// worker whose identity is three-quarters empty. Config's contract genuinely
// does require all four - Identity.validate rejects any blank, and these refs
// are bound as the principal of the completion and result_unknown audit lineage,
// so an empty one is an unattributable audit record, not a default.
//
// Three of the four have no configuration surface at all (task B3). The guard's
// job here is to name them, not to pretend the gap can be satisfied.
var requiredIdentityFields = []string{"PrincipalRef", "AgentClientRef", "AgentReleaseRef", "OrgSnapshotRef"}

// MissingRequired reports every dependency this Config leaves unsatisfied,
// sorted: the nil execution seams, plus the Identity refs left blank, named as
// "Identity.<Field>".
//
// An empty result means the worker can be constructed AND has an attributable
// identity. It does not mean any seam works - CheckReady still owns that, and
// still owns the Secret Provider probe.
func (c Config) MissingRequired() []string {
	missing := wiring.MissingRequired(c, optionalWorkerDeps)
	identity := reflect.ValueOf(c.Identity)
	for _, name := range requiredIdentityFields {
		if identity.FieldByName(name).String() == "" {
			missing = append(missing, "Identity."+name)
		}
	}
	sort.Strings(missing)
	return missing
}
