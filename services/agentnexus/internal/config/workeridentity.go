package config

import (
	"fmt"
	"os"
	"strings"
)

// WorkerIdentityConfig is the connector worker's own first-party system
// identity. It is the configuration surface for worker.Identity, which had none
// at all before task B3: cmd/connector-worker supplied its service name as the
// principal and left AgentClientRef, AgentReleaseRef and OrgSnapshotRef blank,
// so worker.Config.MissingRequired named all three as dependencies constructed
// by nobody and the worker could never be built.
//
// These four refs are NOT an Agent identity and are never sourced from a
// dispatch message. They are bound as the principal of the completion and
// result_unknown audit lineage, which is why worker.Identity.validate rejects a
// blank in any of them: a blank ref produces an unattributable audit record
// rather than a defaulted one.
//
// Only PrincipalRef has a legitimate default (the service's own name — it IS
// the acting first-party service). The other three name deployment facts this
// process cannot know: which registered agent client and release the worker
// executes as, and which sealed organization snapshot its authorization is
// evaluated against. Inventing any of them would mint audit lineage pointing at
// a client, release or org snapshot that does not exist.
type WorkerIdentityConfig struct {
	PrincipalRef    string
	AgentClientRef  string
	AgentReleaseRef string
	OrgSnapshotRef  string
}

// Configured reports whether the deployment supplied a worker identity at all.
// An unconfigured identity is not an error: the worker stays unconstructed and
// /readyz says so, which is the honest state for a deployment that has not
// finished wiring rather than a reason to refuse to boot.
func (c WorkerIdentityConfig) Configured() bool {
	return c != WorkerIdentityConfig{}
}

// Complete reports whether every ref worker.Identity requires carries a value.
func (c WorkerIdentityConfig) Complete() bool {
	return c.PrincipalRef != "" && c.AgentClientRef != "" &&
		c.AgentReleaseRef != "" && c.OrgSnapshotRef != ""
}

// Worker identity environment variables.
const (
	envWorkerPrincipalRef    = "AGENTNEXUS_WORKER_PRINCIPAL_REF"
	envWorkerAgentClientRef  = "AGENTNEXUS_WORKER_AGENT_CLIENT_REF"
	envWorkerAgentReleaseRef = "AGENTNEXUS_WORKER_AGENT_RELEASE_REF"
	envWorkerOrgSnapshotRef  = "AGENTNEXUS_WORKER_ORG_SNAPSHOT_REF"
)

// LoadWorkerIdentity reads the connector worker's system identity, defaulting
// only PrincipalRef to serviceName.
//
// The three remaining refs are ALL-OR-NOTHING, on the LoadEvidence and
// AGENTNEXUS_APPROVAL_CHANNEL precedent: supplying some of them is a startup
// error rather than a silent partial identity. The failure mode that rule
// exists to prevent is specific here — a partially configured identity would be
// rejected later by worker.Identity.validate as a flat "requires principal_ref,
// agent_client_ref, agent_release_ref and org_snapshot_ref", which does not tell
// an operator WHICH of the ones they set was missed.
//
// Supplying none of them returns the zero config with no error. That is the
// deployment that has not wired the worker yet, and it must keep booting so its
// health surface stays observable.
func LoadWorkerIdentity(serviceName string) (WorkerIdentityConfig, error) {
	principal := strings.TrimSpace(os.Getenv(envWorkerPrincipalRef))
	clientRef := strings.TrimSpace(os.Getenv(envWorkerAgentClientRef))
	releaseRef := strings.TrimSpace(os.Getenv(envWorkerAgentReleaseRef))
	orgRef := strings.TrimSpace(os.Getenv(envWorkerOrgSnapshotRef))

	if principal == "" && clientRef == "" && releaseRef == "" && orgRef == "" {
		return WorkerIdentityConfig{}, nil
	}
	var missing []string
	for _, entry := range []struct{ name, value string }{
		{envWorkerAgentClientRef, clientRef},
		{envWorkerAgentReleaseRef, releaseRef},
		{envWorkerOrgSnapshotRef, orgRef},
	} {
		if entry.value == "" {
			missing = append(missing, entry.name)
		}
	}
	if len(missing) > 0 {
		return WorkerIdentityConfig{}, fmt.Errorf(
			"the connector worker identity needs %s, %s and %s together (%s defaults to the service name); missing: %s",
			envWorkerAgentClientRef, envWorkerAgentReleaseRef, envWorkerOrgSnapshotRef,
			envWorkerPrincipalRef, strings.Join(missing, ", "))
	}
	if principal == "" {
		principal = serviceName
	}
	return WorkerIdentityConfig{
		PrincipalRef:    principal,
		AgentClientRef:  clientRef,
		AgentReleaseRef: releaseRef,
		OrgSnapshotRef:  orgRef,
	}, nil
}
