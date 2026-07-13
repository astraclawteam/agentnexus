package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

// envelopeOverheadBytes is the headroom the raw-stdout memory guard allows above
// the semantic output ceiling for the response envelope's own JSON fields
// (protocol version, request id, status, hash). It keeps a valid response whose
// Output sits at the ceiling from being rejected by the stream guard, while the
// supervisor still enforces the precise per-connector Output ceiling.
const envelopeOverheadBytes = 4096

// Process adapter sentinels.
var (
	// ErrConnectorProcessFailed marks a connector child process that exited
	// non-zero or could not be run.
	ErrConnectorProcessFailed = errors.New("connector process failed")
	// errOutputOverflow marks a connector child whose raw response stream exceeded
	// the host-memory guard (the semantic output ceiling plus envelope headroom).
	// The supervisor maps it to a bounded resource failure.
	errOutputOverflow = errors.New("connector response stream exceeded ceiling")
)

// resourceLimits are the per-run resource bounds a containment enforces at the
// OS level where it can. On Windows the Job Object caps active process count and
// total job memory; on Unix these are not enforced through os/exec (see
// process_unix.go) and the container adapter's cgroups are the hard-cap boundary.
type resourceLimits struct {
	memoryBytes int64
	pidsLimit   int
}

// ProcessAdapter runs a connector as a bounded child process that speaks the
// host RPC over stdin/stdout.
//
// SCOPE — it confines the connector's LIFECYCLE and RESOURCES, not its syscalls.
// It contains and reaps the child's entire process tree (a Windows Job Object
// with an active-process and job-memory limit; a Unix process group that is
// killed as a whole), bounds the response stream in host memory, and honors the
// wall-clock deadline. It runs a plain exec.Command: there is NO chroot, mount
// namespace, network namespace or seccomp filter. The supervisor's filesystem
// and egress policy checks are therefore ADVISORY on this path — they validate
// only the access a cooperative connector DECLARES; a hostile connector can read
// or reach anything the host process can. Real syscall-level filesystem and
// network confinement is the container adapter's job (read-only rootfs, mounted
// roots, restricted egress). Untrusted connectors MUST run under the container
// adapter; the process adapter is for first-party or already-sandboxed connectors.
type ProcessAdapter struct {
	// Command and Args launch the connector process.
	Command string
	Args    []string
	// Env is the child environment. A nil Env inherits the host environment.
	Env []string
}

// Name identifies the adapter for audit.
func (a *ProcessAdapter) Name() string { return "process" }

// Dispatch feeds the connector its request, bounds its response stream in host
// memory, kills its whole process tree on timeout or completion, and decodes the
// response. The child is contained BEFORE it can run (started suspended and
// assigned to the job on Windows; a process-group leader on Unix), so even a
// grandchild the connector spawns as its first action is created inside the
// containment and reaped with it.
func (a *ProcessAdapter) Dispatch(ctx context.Context, policy Policy, req *HostRequest) (*HostResponse, error) {
	reqBytes, err := EncodeHostRequest(req)
	if err != nil {
		return nil, err
	}

	cont, err := newContainment(resourceLimits{memoryBytes: policy.MemoryBytes, pidsLimit: policy.PidsLimit})
	if err != nil {
		return nil, fmt.Errorf("connector containment: %w", err)
	}
	defer cont.release()

	cmd := exec.Command(a.Command, a.Args...)
	if a.Env != nil {
		cmd.Env = a.Env
	}
	cont.prepare(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	// Bound the RAW response stream in host memory so a firehose child cannot
	// exhaust the host. This guard is the semantic output ceiling plus a small
	// envelope headroom; the supervisor applies the precise per-connector
	// MaxOutputBytes ceiling to the decoded Output field, uniformly for every
	// adapter. The two are intentionally layered: memory safety here, semantic
	// truncation there.
	out := &cappedBuffer{limit: outputMemoryGuard(policy.MaxOutputBytes)}
	cmd.Stdout = out
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectorProcessFailed, err)
	}

	// Contain the running child before feeding it the request. Ordering matters:
	// the connector reads its request from stdin, and we only write stdin after
	// containment, so any process the connector spawns is inside the containment.
	if err := cont.started(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("connector containment assign: %w", err)
	}

	go func() {
		_, _ = stdin.Write(reqBytes)
		_ = stdin.Close()
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		// Budget exceeded or caller cancelled: kill the whole tree and reap it.
		cont.terminate()
		<-waitCh
		return nil, ctx.Err()
	case werr := <-waitCh:
		// The connector returned. Kill any descendants it may have left behind so
		// no orphan survives the operation, then bound and decode the response.
		cont.terminate()
		if out.overflowed() {
			return nil, errOutputOverflow
		}
		if werr != nil {
			return nil, fmt.Errorf("%w: %v", ErrConnectorProcessFailed, werr)
		}
		resp, derr := DecodeHostResponse(out.Bytes())
		if derr != nil {
			return nil, derr
		}
		return resp, nil
	}
}

// outputMemoryGuard is the raw-stdout byte ceiling: the semantic output ceiling
// plus the envelope headroom, so a valid response is never rejected by the
// stream guard while a firehose still is.
func outputMemoryGuard(maxOutputBytes int) int {
	if maxOutputBytes <= 0 {
		maxOutputBytes = DefaultMaxOutputBytes
	}
	return maxOutputBytes + envelopeOverheadBytes
}

// cappedBuffer accumulates a connector's stdout up to a hard byte ceiling. Once
// the ceiling is reached it records the overflow and discards further bytes,
// reporting a full write so the child's stdout copier neither blocks nor errors
// before the supervisor kills it. It is safe for the os/exec copy goroutine and
// the Dispatch goroutine to touch concurrently.
type cappedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.over {
		return len(p), nil
	}
	remaining := c.limit - c.buf.Len()
	if remaining <= 0 {
		c.over = true
		return len(p), nil
	}
	if len(p) > remaining {
		c.buf.Write(p[:remaining])
		c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Bytes()
}

func (c *cappedBuffer) overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.over
}
