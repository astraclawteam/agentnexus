package config

import (
	"strings"
	"testing"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
)

// setWorkerIdentityEnv sets exactly the four identity variables (t.Setenv
// restores them), so each case states its whole environment rather than
// inheriting whatever a previous one left behind.
func setWorkerIdentityEnv(t *testing.T, principal, client, release, org string) {
	t.Helper()
	t.Setenv(envWorkerPrincipalRef, principal)
	t.Setenv(envWorkerAgentClientRef, client)
	t.Setenv(envWorkerAgentReleaseRef, release)
	t.Setenv(envWorkerOrgSnapshotRef, org)
}

// An unconfigured deployment is not an error. cmd/connector-worker must still
// boot and answer /readyz with the reason it cannot consume; refusing to start
// would replace an observable health surface with a crash loop.
func TestLoadWorkerIdentityIsEmptyAndErrorFreeWhenNothingIsSet(t *testing.T) {
	setWorkerIdentityEnv(t, "", "", "", "")
	cfg, err := LoadWorkerIdentity("connector-worker")
	if err != nil {
		t.Fatalf("an unconfigured worker identity must not be a startup error: %v", err)
	}
	if cfg.Configured() || cfg.Complete() {
		t.Fatalf("LoadWorkerIdentity() = %+v, want the zero config", cfg)
	}
}

func TestLoadWorkerIdentityDefaultsOnlyThePrincipalRef(t *testing.T) {
	setWorkerIdentityEnv(t, "", "agc_console", "agr_2026_07", "orgv_7")
	cfg, err := LoadWorkerIdentity("connector-worker")
	if err != nil {
		t.Fatalf("LoadWorkerIdentity: %v", err)
	}
	want := WorkerIdentityConfig{
		PrincipalRef:    "connector-worker",
		AgentClientRef:  "agc_console",
		AgentReleaseRef: "agr_2026_07",
		OrgSnapshotRef:  "orgv_7",
	}
	if cfg != want {
		t.Fatalf("LoadWorkerIdentity() = %+v, want %+v", cfg, want)
	}
	if !cfg.Complete() {
		t.Fatal("a config with all four refs must report Complete")
	}
}

// The all-or-nothing rule, one omission at a time. The error must NAME the
// variable that was missed: worker.Identity.validate would otherwise reject the
// result later with a flat list of all four, which does not tell an operator
// which of the ones they set was wrong.
func TestLoadWorkerIdentityRejectsAPartialSetAndNamesWhatIsMissing(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		client, release, org string
		wantNamed            string
	}{
		{"no agent client ref", "", "agr_2026_07", "orgv_7", envWorkerAgentClientRef},
		{"no agent release ref", "agc_console", "", "orgv_7", envWorkerAgentReleaseRef},
		{"no org snapshot ref", "agc_console", "agr_2026_07", "", envWorkerOrgSnapshotRef},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setWorkerIdentityEnv(t, "worker-1", tc.client, tc.release, tc.org)
			cfg, err := LoadWorkerIdentity("connector-worker")
			if err == nil {
				t.Fatalf("a partial identity must be a startup error, got %+v", cfg)
			}
			if !strings.Contains(err.Error(), "missing: "+tc.wantNamed) {
				t.Fatalf("error must name %s as missing, got %v", tc.wantNamed, err)
			}
			if cfg.Configured() {
				t.Fatalf("a rejected load must return the zero config, got %+v", cfg)
			}
		})
	}
}

// Setting ONLY the principal is the shape cmd/connector-worker shipped in
// before B3 (its service name and nothing else). It must now be an explicit
// error rather than a three-quarters-empty identity.
func TestLoadWorkerIdentityRejectsThePrincipalOnlyShape(t *testing.T) {
	setWorkerIdentityEnv(t, "connector-worker", "", "", "")
	if _, err := LoadWorkerIdentity("connector-worker"); err == nil {
		t.Fatal("a principal-only identity must be rejected; it is the exact pre-B3 gap")
	}
}

// The contract this config exists to satisfy. Asserting against
// worker.Config.MissingRequired rather than against a copy of the field list is
// what keeps the two from drifting: adding a fifth required Identity ref would
// fail here rather than silently leave this loader one short.
func TestLoadedWorkerIdentitySatisfiesTheWorkerWiringGuard(t *testing.T) {
	setWorkerIdentityEnv(t, "", "agc_console", "agr_2026_07", "orgv_7")
	cfg, err := LoadWorkerIdentity("connector-worker")
	if err != nil {
		t.Fatalf("LoadWorkerIdentity: %v", err)
	}
	identity := worker.Identity{
		PrincipalRef:    cfg.PrincipalRef,
		AgentClientRef:  cfg.AgentClientRef,
		AgentReleaseRef: cfg.AgentReleaseRef,
		OrgSnapshotRef:  cfg.OrgSnapshotRef,
	}
	unwired := worker.Config{Identity: identity}.MissingRequired()
	for _, name := range unwired {
		if strings.HasPrefix(name, "Identity.") {
			t.Errorf("a completely loaded identity still leaves %s unsatisfied", name)
		}
	}
}
