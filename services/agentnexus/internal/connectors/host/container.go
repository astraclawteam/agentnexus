package host

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// ErrContainerRuntimeUnavailable marks a container Dispatch attempted where no
// container runtime is reachable. On a developer box without a container daemon
// this is the honest, fail-closed outcome: the adapter derives a correct spec
// but refuses to claim it executed. The supervisor turns it into a bounded
// StatusFailed, never a crash.
var ErrContainerRuntimeUnavailable = errors.New("container runtime unavailable")

// ContainerMount is one filesystem root mounted into the connector container.
type ContainerMount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// ContainerNetwork is the container's network posture: an isolation mode plus
// the exact set of allowed egress targets. Nothing outside AllowedEgress is
// reachable.
type ContainerNetwork struct {
	Isolation     string       `json:"isolation"`
	AllowedEgress []EgressRule `json:"allowed_egress"`
}

// ContainerResources is the container's enforced resource envelope. A real
// runtime maps these onto cgroup cpu/memory/pids limits and a wall-clock
// deadline.
type ContainerResources struct {
	CPUBudget   time.Duration `json:"cpu_budget"`
	MemoryBytes int64         `json:"memory_bytes"`
	WallClock   time.Duration `json:"wall_clock"`
	PidsLimit   int           `json:"pids_limit"`
}

// ContainerSpec is the concrete, inspectable container/namespace specification
// the container adapter derives from a Policy. Its correctness (read-only
// rootfs, dropped capabilities, no-new-privileges, restricted network, only
// allowed FS roots mounted, resource limits present, digest pinned) is what the
// spec-correctness fixtures assert, standing in for real container execution
// which is deferred to CI/release.
type ContainerSpec struct {
	Image               string             `json:"image"`
	Runtime             string             `json:"runtime"`
	PackageDigest       string             `json:"package_digest"`
	ReadOnlyRootfs      bool               `json:"read_only_rootfs"`
	NoNewPrivileges     bool               `json:"no_new_privileges"`
	DroppedCapabilities []string           `json:"dropped_capabilities"`
	ContainProcesses    bool               `json:"contain_processes"`
	Network             ContainerNetwork   `json:"network"`
	Mounts              []ContainerMount   `json:"mounts"`
	Resources           ContainerResources `json:"resources"`
	Env                 []string           `json:"env,omitempty"`
	WorkingDir          string             `json:"working_dir"`
}

// ContainerAdapter runs a connector as a container. It derives a locked-down
// ContainerSpec from the same manifest-derived Policy the process adapter uses.
// On a box with no container runtime, Dispatch derives the spec and then fails
// closed with ErrContainerRuntimeUnavailable rather than pretending to execute.
type ContainerAdapter struct {
	// Image is the connector container image, pinned by digest.
	Image string
	// Runtime names the container runtime (informational; a real launcher
	// selects the OCI/appliance runtime).
	Runtime string
	// launch, when set, executes the derived spec. It is nil on this box (no
	// runtime); tests and CI/release wire a real launcher. Keeping it a field
	// keeps Dispatch honest: absent a launcher it fails closed.
	launch func(ctx context.Context, spec ContainerSpec, req *HostRequest) (*HostResponse, error)
}

// Name identifies the adapter for audit.
func (a *ContainerAdapter) Name() string { return "container" }

// Spec derives the locked-down container specification from the policy and
// request. Every field is a direct, auditable function of the Policy; nothing is
// left to a permissive default.
func (a *ContainerAdapter) Spec(policy Policy, req *HostRequest) ContainerSpec {
	isolation := "restricted"
	if len(policy.Egress) == 0 {
		isolation = "none"
	}
	mounts := make([]ContainerMount, 0, len(policy.FSRoots))
	for _, root := range policy.FSRoots {
		mounts = append(mounts, ContainerMount{
			Source:   root,
			Target:   filepath.ToSlash(filepath.Join("/sandbox", filepath.Base(root))),
			ReadOnly: !requestWritesRoot(req, root),
		})
	}
	workingDir := "/sandbox"
	if len(mounts) > 0 {
		workingDir = mounts[0].Target
	}
	return ContainerSpec{
		Image:               a.Image,
		Runtime:             a.Runtime,
		PackageDigest:       policy.ExpectedDigest,
		ReadOnlyRootfs:      true,
		NoNewPrivileges:     true,
		DroppedCapabilities: []string{"ALL"},
		ContainProcesses:    true,
		Network: ContainerNetwork{
			Isolation:     isolation,
			AllowedEgress: append([]EgressRule(nil), policy.Egress...),
		},
		Mounts: mounts,
		Resources: ContainerResources{
			CPUBudget:   policy.CPUBudget,
			MemoryBytes: policy.MemoryBytes,
			WallClock:   policy.WallClock,
			PidsLimit:   policy.PidsLimit,
		},
		WorkingDir: workingDir,
	}
}

// requestWritesRoot reports whether the request declares a write under root, so
// the container mounts that root writable rather than read-only. Absent a
// declared write a root is mounted read-only, keeping least privilege the
// default.
func requestWritesRoot(req *HostRequest, root string) bool {
	if req == nil {
		return false
	}
	for _, fa := range req.Filesystem {
		if fa.Write && pathWithinRoot(root, fa.Path) {
			return true
		}
	}
	return false
}

// Dispatch derives the spec and, absent a wired container runtime, fails closed.
// The spec is derived first so any policy/spec error surfaces before the
// runtime-unavailable outcome, keeping the failure deterministic and bounded.
func (a *ContainerAdapter) Dispatch(ctx context.Context, policy Policy, req *HostRequest) (*HostResponse, error) {
	spec := a.Spec(policy, req)
	if a.launch == nil {
		return nil, fmt.Errorf("%w: no container runtime is wired on this host (spec digest %s)", ErrContainerRuntimeUnavailable, spec.PackageDigest)
	}
	return a.launch(ctx, spec, req)
}
