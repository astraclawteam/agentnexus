//go:build !windows

package host

import (
	"errors"
	"os/exec"
	"syscall"
)

// containment contains a connector process and its entire descendant tree in a
// dedicated process group. Killing the negative group id reaps the child and any
// grandchildren it spawned.
//
// SCOPE: this bounds the connector's LIFECYCLE only. It does NOT hard-cap CPU,
// memory or process count: per-child setrlimit is not expressible through
// os/exec without a pre-exec hook (cgo) or a launcher wrapper, and setting a
// limit on the host process would wrongly constrain the host itself. Those hard
// caps are the container adapter's cgroup boundary (memory/pids/cpu), and the
// supervisor's wall-clock timeout is the portable runtime backstop. The
// resourceLimits are accepted for interface symmetry and documented honestly
// here; they are not silently enforced on this path.
type containment struct {
	pgid int
}

func newContainment(_ resourceLimits) (*containment, error) { return &containment{}, nil }

// prepare makes the child a new process-group leader before it starts, so its
// descendants share one killable group.
func (c *containment) prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// started records the group id once the child is running. The group id equals
// the child pid because the child is the group leader.
func (c *containment) started(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		c.pgid = cmd.Process.Pid
	}
	return nil
}

// terminate kills the whole process group. It is idempotent: a group that is
// already gone yields ESRCH, which is not an error here.
func (c *containment) terminate() {
	if c.pgid > 0 {
		_ = syscall.Kill(-c.pgid, syscall.SIGKILL)
	}
}

// release frees OS resources. The process group needs none beyond the kill.
func (c *containment) release() {}

// processAlive reports whether a process with pid currently exists. Signal 0
// performs the existence/permission check without delivering a signal.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	// EPERM means the process exists but is owned by another user.
	return errors.Is(err, syscall.EPERM)
}
