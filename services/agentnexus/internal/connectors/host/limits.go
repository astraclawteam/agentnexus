package host

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
)

// Policy sentinels. Callers match these with errors.Is.
var (
	// ErrDigestMismatch marks a connector package whose content digest does not
	// match the digest the Customer Binding pinned (ProductRef.Digest). A
	// digest-swapped pack is refused before any execution.
	ErrDigestMismatch = errors.New("connector package digest does not match pinned product reference digest")
	// ErrPathOutsideSandbox marks a filesystem path outside the connector's
	// allowed sandbox roots (absolute escape or parent traversal).
	ErrPathOutsideSandbox = errors.New("filesystem path is outside the connector sandbox roots")
	// ErrEgressNotAllowed marks a network target not permitted by the
	// manifest-derived egress allow-list.
	ErrEgressNotAllowed = errors.New("network egress target is not permitted by connector policy")
	// ErrPolicyInvalid marks a policy that cannot be derived from the pack and
	// binding (missing digest, contradictory limits).
	ErrPolicyInvalid = errors.New("connector host policy invalid")
)

// Host-enforced defaults. The Product Pack and Customer Binding express the
// business/network contract (egress classes, concrete endpoints, memory floor,
// rate limits, package digest) but NOT low-level execution budgets (CPU time,
// wall-clock, filesystem roots). Where the manifest is silent, the host applies
// conservative, documented defaults so an operation is always bounded.
//
// Enforcement of these budgets differs by adapter, and the comments below say
// exactly which adapter enforces which bound — no default implies an
// enforcement its adapter does not perform:
//   - WallClock and MaxOutputBytes are enforced by the SUPERVISOR for every
//     adapter (timeout kill; Output-field truncation).
//   - CPUBudget and MemoryBytes are enforced by the CONTAINER adapter via the
//     ContainerSpec (cgroup cpu/memory), with real enforcement deferred to the
//     container runtime in CI/release. The process adapter additionally caps job
//     memory on Windows (Job Object) but does NOT cap CPU time.
//   - PidsLimit is enforced by the CONTAINER adapter (cgroup pids) and by the
//     process adapter's Windows Job Object (active-process limit). It is NOT
//     enforced on the Unix process path (see process_unix.go).
const (
	// DefaultWallClock bounds one connector operation's total run time. Enforced
	// by the supervisor (timeout + kill) on every adapter.
	DefaultWallClock = 30 * time.Second
	// DefaultCPUBudget bounds one connector operation's CPU time. It equals the
	// wall-clock default by construction. It is enforced by the container adapter
	// as a cgroup cpu quota (deferred to the container runtime); the process
	// adapter does NOT cap CPU time (wall-clock is its runtime backstop).
	DefaultCPUBudget = 30 * time.Second
	// DefaultMaxOutputBytes bounds a connector's returned Output. Enforced by the
	// supervisor for every adapter.
	DefaultMaxOutputBytes = 1 << 20 // 1 MiB
	// DefaultMemoryCeilingMB is the host memory ceiling applied when the pack
	// declares no (or a small) memory floor. Enforced by the container adapter
	// (cgroup memory) and by the process adapter's Windows Job Object; not on the
	// Unix process path.
	DefaultMemoryCeilingMB = 512
	// MemoryHeadroomFactor multiplies the pack's declared memory floor to derive
	// a ceiling: the floor is what the connector needs, the ceiling is what the
	// host will let it consume before terminating it.
	MemoryHeadroomFactor = 2
	// DefaultPidsLimit bounds how many processes a connector may run at once.
	// Enforced by the container adapter (cgroup pids) and by the process
	// adapter's Windows Job Object (active-process limit); not on the Unix
	// process path.
	DefaultPidsLimit = 64
)

// EgressRule is one concrete allowed network target (host + port), derived from
// a Customer Binding endpoint.
type EgressRule struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Policy is the manifest-derived sandbox policy for one connector instance. It
// binds the package digest, the resource envelope, the allowed filesystem roots
// and the allowed network egress. Both the process and container adapters derive
// their concrete sandbox from this single struct.
type Policy struct {
	// ConnectorRef is the connector identity (the bound customer name), used as
	// the Secret Handle scope's connector identity.
	ConnectorRef string
	// ExpectedDigest is the pinned Product Pack content digest
	// (binding.Product.Digest). The container adapter pins the connector image to
	// it; the supervisor refuses to build for a mismatching pack.
	ExpectedDigest string
	// Isolation mirrors the pack's declared network isolation posture.
	Isolation string
	// WallClock and CPUBudget bound one operation's run time.
	WallClock time.Duration
	CPUBudget time.Duration
	// MemoryBytes is the host memory ceiling for the connector.
	MemoryBytes int64
	// MaxOutputBytes bounds the connector's returned output.
	MaxOutputBytes int
	// MaxConcurrency and MaxRequestsPerMinute mirror the pack's rate envelope for
	// inspection and downstream propagation only. This isolated-host task does not
	// implement concurrency or rate limiting; these are NOT active runtime bounds
	// here and are surfaced so a scheduler/gateway can enforce them.
	MaxConcurrency       int
	MaxRequestsPerMinute int
	// PidsLimit bounds the connector process tree.
	PidsLimit int
	// FSRoots are the only filesystem roots the connector may touch.
	FSRoots []string
	// Egress is the only set of network targets the connector may reach.
	Egress []EgressRule
	// ContainProcesses requires the runtime to contain and reap the connector's
	// entire process tree (job object / process group / PID namespace).
	ContainProcesses bool
}

type deriveConfig struct {
	sandboxRoots   []string
	wallClock      time.Duration
	cpuBudget      time.Duration
	maxOutputBytes int
}

// DeriveOption customizes the host-enforced defaults the manifest does not
// express. The security-critical inputs (allowed egress, package digest) are
// always derived from the pack/binding and can NOT be overridden by an option.
type DeriveOption func(*deriveConfig)

// WithSandboxRoots sets the filesystem roots the connector may touch. The
// manifest does not declare filesystem roots, so the host supplies an
// operation-scoped sandbox (typically a per-operation working directory).
func WithSandboxRoots(roots ...string) DeriveOption {
	return func(c *deriveConfig) { c.sandboxRoots = append(c.sandboxRoots, roots...) }
}

// WithWallClock overrides the wall-clock (and CPU) budget.
func WithWallClock(d time.Duration) DeriveOption {
	return func(c *deriveConfig) {
		if d > 0 {
			c.wallClock = d
			c.cpuBudget = d
		}
	}
}

// WithMaxOutputBytes overrides the output ceiling.
func WithMaxOutputBytes(n int) DeriveOption {
	return func(c *deriveConfig) {
		if n > 0 {
			c.maxOutputBytes = n
		}
	}
}

// DerivePolicy derives the sandbox policy from a Product Pack and its Customer
// Binding. It FIRST verifies the pack's content digest matches the digest the
// binding pinned (ProductRef.Digest); a mismatch is ErrDigestMismatch, so a
// digest-swapped pack can never be turned into a runnable policy. The allowed
// egress is derived from the binding's concrete endpoints gated by the pack's
// declared network posture; the memory ceiling from the pack's memory floor; the
// rate envelope from the pack's limits. Low-level execution budgets fall back to
// documented host defaults.
func DerivePolicy(pack connector.ProductPack, binding connector.CustomerBinding, opts ...DeriveOption) (Policy, error) {
	cfg := deriveConfig{
		wallClock:      DefaultWallClock,
		cpuBudget:      DefaultCPUBudget,
		maxOutputBytes: DefaultMaxOutputBytes,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Digest binding: the running pack MUST be the exact pack the binding was
	// paired with. This uses the same content-digest helper Task 2 signs over.
	pinned := strings.TrimSpace(binding.Product.Digest)
	if pinned == "" {
		return Policy{}, fmt.Errorf("%w: binding pins no product digest", ErrPolicyInvalid)
	}
	if actual := connector.PackContentDigest(pack); actual != pinned {
		return Policy{}, fmt.Errorf("%w: pack %s, binding pinned %s", ErrDigestMismatch, actual, pinned)
	}

	egress, err := deriveEgress(pack.Network, binding.Endpoints)
	if err != nil {
		return Policy{}, err
	}

	roots, err := cleanRoots(cfg.sandboxRoots)
	if err != nil {
		return Policy{}, err
	}

	policy := Policy{
		ConnectorRef:         connectorRef(binding),
		ExpectedDigest:       pinned,
		Isolation:            pack.Network.Isolation,
		WallClock:            cfg.wallClock,
		CPUBudget:            cfg.cpuBudget,
		MemoryBytes:          deriveMemoryCeiling(pack.Runtime),
		MaxOutputBytes:       cfg.maxOutputBytes,
		MaxConcurrency:       pack.Limits.MaxConcurrency,
		MaxRequestsPerMinute: pack.Limits.MaxRequestsPerMinute,
		PidsLimit:            DefaultPidsLimit,
		FSRoots:              roots,
		Egress:               egress,
		ContainProcesses:     true,
	}
	return policy, nil
}

// connectorRef resolves the connector identity used for the Secret Handle scope.
// The bound customer name is the connector identity in this codebase's runtime
// (see internal/connectors/runtime), so mirror it here.
func connectorRef(binding connector.CustomerBinding) string {
	if binding.Customer.Name != "" {
		return binding.Customer.Name
	}
	return binding.BindingKey
}

// deriveMemoryCeiling turns the pack's memory floor into a host ceiling. The
// floor (MinMemoryMB) is what the connector needs; the ceiling is what the host
// will allow before terminating it. A pack that declares no floor gets the
// default ceiling.
func deriveMemoryCeiling(rt connector.RuntimeRequirements) int64 {
	ceilingMB := DefaultMemoryCeilingMB
	if rt.MinMemoryMB > 0 {
		scaled := rt.MinMemoryMB * MemoryHeadroomFactor
		if scaled > ceilingMB {
			ceilingMB = scaled
		}
	}
	return int64(ceilingMB) * 1024 * 1024
}

// deriveEgress computes the concrete allowed egress targets from the binding's
// endpoints, gated by the pack's declared network posture. The allow-list is
// derived from the pack/binding, never hardcoded: an isolated pack (or one that
// declares no egress classes) permits no egress at all.
func deriveEgress(network connector.NetworkRequirements, endpoints []connector.Endpoint) ([]EgressRule, error) {
	if len(network.Egress) == 0 || strings.EqualFold(network.Isolation, "isolated") || strings.EqualFold(network.Isolation, "none") {
		return nil, nil
	}
	var rules []EgressRule
	seen := map[string]bool{}
	for _, ep := range endpoints {
		host, port, err := hostPort(ep.URL)
		if err != nil {
			return nil, fmt.Errorf("%w: binding endpoint %q: %v", ErrPolicyInvalid, ep.Name, err)
		}
		key := host + ":" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, EgressRule{Host: host, Port: port})
	}
	return rules, nil
}

// hostPort parses a binding endpoint URL into a host and a concrete port,
// resolving the default port from the scheme when the URL omits it.
func hostPort(raw string) (string, int, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0, err
	}
	host := u.Hostname()
	if host == "" {
		return "", 0, fmt.Errorf("endpoint %q has no host", raw)
	}
	if p := u.Port(); p != "" {
		port, err := net.LookupPort("tcp", p)
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss":
		return host, 443, nil
	case "http", "ws":
		return host, 80, nil
	default:
		return "", 0, fmt.Errorf("endpoint %q has no port and an unknown scheme %q", raw, u.Scheme)
	}
}

func cleanRoots(roots []string) ([]string, error) {
	cleaned := make([]string, 0, len(roots))
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("%w: sandbox root %q: %v", ErrPolicyInvalid, root, err)
		}
		cleaned = append(cleaned, filepath.Clean(abs))
	}
	return cleaned, nil
}

// AllowPath reports whether the connector may touch path. A path is allowed only
// when it resolves (after cleaning) inside one of the configured sandbox roots.
// With no roots configured the host fails closed: every path is denied.
func (p Policy) AllowPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: empty path", ErrPathOutsideSandbox)
	}
	for _, root := range p.FSRoots {
		if pathWithinRoot(root, path) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrPathOutsideSandbox, path)
}

// pathWithinRoot reports whether path resolves inside root after cleaning. It
// rejects parent traversal ("..") and, on Windows, a different-volume path
// (filepath.Rel yields an absolute or "..-prefixed" result for those). It is the
// single containment predicate the filesystem policy and the container mount
// derivation share.
func pathWithinRoot(root, path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, filepath.Clean(abs))
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

// AllowEgress reports whether the connector may reach host:port. Only the
// concrete targets derived from the binding endpoints are allowed.
func (p Policy) AllowEgress(host string, port int) error {
	host = strings.TrimSpace(host)
	for _, rule := range p.Egress {
		if strings.EqualFold(rule.Host, host) && rule.Port == port {
			return nil
		}
	}
	return fmt.Errorf("%w: %s:%d", ErrEgressNotAllowed, host, port)
}

// checkAccess validates every declared filesystem access and network target
// against the policy, returning the first violation. The supervisor calls it as
// the single pre-dispatch access gate.
//
// NOTE: on the process adapter path this gate is ADVISORY — it validates only
// what a cooperative connector declares (see ProcessAdapter). The container
// adapter is the boundary that makes the same policy binding at the syscall
// level (read-only rootfs, mounted-only roots, restricted egress).
func (p Policy) checkAccess(filesystem []FileAccess, network []NetworkTarget) error {
	for _, fa := range filesystem {
		if err := p.AllowPath(fa.Path); err != nil {
			return err
		}
	}
	for _, nt := range network {
		if err := p.AllowEgress(nt.Host, nt.Port); err != nil {
			return err
		}
	}
	return nil
}
