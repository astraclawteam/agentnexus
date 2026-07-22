package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/agenttrust"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresGatewayConfig is the complete production dependency contract for the
// browser gateway. Keeping the wiring here lets cmd/gateway-api and the live
// PostgreSQL acceptance suite exercise exactly the same stores and router.
type PostgresGatewayConfig struct {
	ServiceName                 string
	Version                     string
	OIDC                        browserauth.OIDCConfig
	LoginAttemptLimits          browserauth.LoginAttemptLimits
	AuthorizeRateLimitPerMinute int
	TrustedProxyCIDRs           []netip.Prefix
	// ApprovalChannel is the configured outbound channel to the external
	// approval system (AgentAtlas/OA/BPM). When nil the approval transmission
	// endpoints stay UNREGISTERED: fail closed, no resolution fallback
	// (GA Task 0E boundary — AgentNexus never chooses approvers).
	ApprovalChannel approvaltransport.Channel
	RequestTimeout  time.Duration
	// AuditSigningKeyID / AuditSigningKey wire the GA Task 0G audit signer. A
	// production deployment MUST supply a STABLE key (a KMS wires behind the
	// audit.AuditSigner port later) so there is a stable signing identity to pin
	// as the offline verifier's trust anchor. Its public half is registered so
	// the offline verifier can resolve it. If no key is configured, router
	// construction FAILS CLOSED unless AllowEphemeralAuditKey is explicitly set.
	AuditSigningKeyID string
	AuditSigningKey   ed25519.PrivateKey
	// AllowEphemeralAuditKey is the DEV-ONLY escape hatch: when true and no
	// stable key is configured, a fresh ephemeral ed25519 key is generated per
	// process (its public half is still registered, but it is NOT a stable trust
	// anchor). Never set this in production - an ephemeral per-process signing
	// identity cannot be pinned and defeats offline verification authenticity.
	AllowEphemeralAuditKey bool
	// DispatchPublisher delivers durable dispatch intents to the connector
	// host (NATS JetStream). Without it the transactional outbox still commits
	// every intent, but nothing ever carries one out of the database: Actions
	// reach `dispatched` and stop there. Optional so a deployment without a
	// message bus still serves the browser and audit surfaces.
	DispatchPublisher actions.Publisher
	// DispatchRecoveryInterval paces the outbox recovery pump. Zero selects
	// defaultDispatchRecoveryInterval. The pump only runs when a publisher is
	// configured — there is nothing to recover to otherwise.
	DispatchRecoveryInterval time.Duration
	// EvidenceObjectRoot / EvidenceContentKeyRef / EvidenceContentKey compose
	// the GA Task 0D semantic evidence runtime behind /v1/runtime/locate and
	// /v1/runtime/read. All three together or none: with none the endpoints stay
	// UNREGISTERED (historical behaviour), with a partial set router
	// construction FAILS CLOSED.
	//
	// EvidenceContentKeyRef must be STABLE across restarts and redeploys. Read
	// resolves a handle's key through the reference persisted at locate time, so
	// a changed ref (or changed material under the same ref) makes every
	// previously staged handle undecryptable — a fail-closed 503 with no hint
	// that key rotation caused it. This mirrors the AuditSigningKeyID/
	// AuditSigningKey contract above, deliberately WITHOUT an ephemeral escape
	// hatch: an ephemeral audit key still signs new events, an ephemeral content
	// key destroys staged content.
	EvidenceObjectRoot    string
	EvidenceContentKeyRef string
	EvidenceContentKey    []byte
	// EvidenceSourceCatalog is the deployment-authored private semantic
	// registry: which business-semantic data classes exist, which connector
	// binding of migration 000012 supplies each, and which organization-placed
	// capability authorizes reading it. It is the FOURTH member of the
	// all-or-nothing set above, not an optional extra.
	//
	// It has to be required for the same reason a content key is. Without a
	// catalog the registry is empty, GetSourceBinding returns ErrNotFound for
	// every data class, and locate denies at not_resolvable before it reaches a
	// content source — a plane that registers /v1/runtime/locate, reports
	// healthy to every probe, and refuses everything. Making it optional would
	// leave that shape reachable by omission, which is exactly how it went
	// unnoticed before.
	EvidenceSourceCatalog evidence.SourceCatalog
}

// defaultDispatchRecoveryInterval paces the outbox recovery drain. It only
// matters after a crash between the outbox commit and the publish, so it is
// tuned for bounded recovery latency rather than throughput.
const defaultDispatchRecoveryInterval = 30 * time.Second

// NewPostgresGatewayRouter composes the browser gateway. It also returns the
// outbox recovery pump when a dispatch publisher is configured; the caller owns
// that goroutine. The pump is returned rather than started here so a test or a
// one-shot command can compose the router without a background loop.
func NewPostgresGatewayRouter(ctx context.Context, pool *pgxpool.Pool, cfg PostgresGatewayConfig) (http.Handler, *actions.RecoveryPump, error) {
	if pool == nil || ctx == nil || cfg.ServiceName == "" || cfg.Version == "" {
		return nil, nil, errors.New("postgres gateway dependencies incomplete")
	}
	upstream, err := browserauth.NewEnterpriseOIDC(ctx, cfg.OIDC)
	if err != nil {
		return nil, nil, err
	}
	directory := NewPostgresBrowserDirectory(pool)
	authorizeRateLimiter, err := browserauth.NewPostgresAuthorizeRateLimiter(pool, cfg.AuthorizeRateLimitPerMinute, time.Now)
	if err != nil {
		return nil, nil, err
	}
	authorizationPolicy := NewPostgresSnapshotSource(pool)
	orgVersions := NewPostgresOrgVersionSource(pool)
	ticketActors := NewPostgresTicketActorAuthenticator(cfg.OIDC.EnterpriseID, pool, time.Now)
	grantStore := NewPostgresGrantStore(pool)
	stepGrantVerifier := NewPostgresStepGrantVerifier(cfg.OIDC.EnterpriseID, grantStore)
	// GA Task 0G audit signer: sign the high-risk action-transition sub-chain and
	// register the public key so the offline verifier resolves it.
	auditSigner, err := buildAuditSigner(ctx, pool, cfg)
	if err != nil {
		return nil, nil, err
	}
	auditSink := NewPostgresBrowserAuditSink(pool, WithAuditSigner(auditSigner))
	grantService := tickets.NewService(grantStore, tickets.WithGrantAuthorizer(NewScopedGrantAuthorizer(grantStore, policy.NewCapabilityEvaluator(authorizationPolicy, policy.WithSnapshotIntegrityObserver(snapshotIntegrityLogger{})))))
	var approvalTransmission ApprovalTransmissionService
	if cfg.ApprovalChannel != nil {
		transmissionService, err := approvaltransport.NewService(approvaltransport.NewPostgresStore(pool), cfg.ApprovalChannel, approvalTransportAuditSink{sink: auditSink})
		if err != nil {
			return nil, nil, err
		}
		approvalTransmission = transmissionService
	}
	// GA Task 0F durable controlled-execution plane. The one-shot approval
	// evidence consumption is backed by the approvaltransport ConsumeEvidence
	// store path; the decision-provider/attestation trust seams stay at their
	// SECURE nil default (a certified third party fails closed, an untrusted
	// caller is always denied) until the agenttrust client-ref -> release join
	// and the authority-key registry are available (0C/0G).
	actionStore := actions.NewPostgresStore(pool)
	// GA Task 0G receipt verification: only a receipt bearing a verified ed25519
	// signature by a REGISTERED, non-revoked connector key completes an Action.
	// The resolver reads the signing-key registry live (dynamic revocation).
	actionOptions := []actions.Option{
		actions.WithEvidenceConsumer(actionEvidenceConsumer{store: approvaltransport.NewPostgresStore(pool)}),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(postgresSigningKeyResolver{pool: pool})),
	}
	if cfg.DispatchPublisher != nil {
		actionOptions = append(actionOptions, actions.WithPublisher(cfg.DispatchPublisher))
	}
	actionService, err := actions.NewService(actionStore, actionAuditSink{sink: auditSink}, actionOptions...)
	if err != nil {
		return nil, nil, err
	}
	// The outbox recovery pump exists only when there is somewhere to recover
	// to. Constructing it without a publisher would give a loop that can never
	// succeed, so it stays nil and the caller starts nothing.
	var recoveryPump *actions.RecoveryPump
	if cfg.DispatchPublisher != nil {
		interval := cfg.DispatchRecoveryInterval
		if interval <= 0 {
			interval = defaultDispatchRecoveryInterval
		}
		recoveryPump, err = actions.NewRecoveryPump(actionService, cfg.OIDC.EnterpriseID, interval)
		if err != nil {
			return nil, nil, err
		}
	}
	// The GA Task 0D semantic evidence runtime. It composes only when the
	// deployment supplies a staging root and a stable content key; unset, both
	// /v1/runtime endpoints stay unregistered exactly as before. The GA Task 0F
	// ActionBindingVerifier is wired INTO it there — that is the wiring the
	// discarded `var _ = actions.NewBindingVerifier(actionStore)` that used to
	// stand at this spot was only pretending to be. There is no separate type
	// assertion left to keep: the real construction type-checks the conformance,
	// and a second one at package scope would be the same decoration again.
	evidenceRuntime, err := buildEvidenceRuntime(ctx, pool, cfg, auditSink, authorizationPolicy, actionStore)
	if err != nil {
		return nil, nil, err
	}
	deps := BrowserAuthDependencies{
		Config:                  cfg.OIDC,
		Sessions:                browserauth.NewService(browserauth.NewPostgresStore(pool), browserauth.WithLoginAttemptLimits(cfg.LoginAttemptLimits)),
		Upstream:                upstream,
		Identities:              directory,
		Profiles:                directory,
		Audit:                   auditSink,
		AuditEvidence:           auditSink,
		AuthorizeRateLimiter:    authorizeRateLimiter,
		AuthorizeSourceResolver: NewAuthorizeSourceResolver(cfg.TrustedProxyCIDRs),
		AuthorizationPolicy:     authorizationPolicy,
		OrgVersions:             orgVersions,
		TicketActors:            ticketActors,
		StepGrants:              stepGrantVerifier,
		ApprovalTransmission:    approvalTransmission,
		Grants:                  grantService,
		Actions:                 actionService,
		Evidence:                evidenceRuntime,
		// The sealed organization change feed. It is a read-only projection of
		// rows the organization-import path already writes, so composing it
		// adds no writer and no second organization authority.
		OrgEvents: NewPostgresOrgEventSource(pool),
		// The GA Task 0C Agent-client trust registry. Its schema (migration
		// 000007), queries, service and tests all predate this wiring; only the
		// HTTP surface and this constructor were missing, which is why three
		// PUBLISHED operations answered a bare 404. It is deliberately NOT
		// deployment-gated: the registry needs no configuration beyond the
		// database the gateway already has, so there is no honest reason for the
		// shipped binary to leave a contracted surface unregistered.
		AgentTrust:     agenttrust.NewService(agenttrust.NewPostgresStore(pool)),
		RequestTimeout: cfg.RequestTimeout,
	}
	// Refuse to compose a gateway that is missing a surface it is contracted to
	// serve. newBrowserAuthHandler's own nil check cannot do this job: it lets
	// every optional surface go unregistered so in-memory tests and reduced
	// routers still work, which is exactly how a dependency can be implemented,
	// unit-tested and constructed by nobody while the suite stays green.
	//
	// Honest limit, carried over from the AgentAtlas side: the unit guarantee
	// below is mutation-provable - break the wiring and TestPostgresGatewayDeps*
	// fails - but "the shipped binary actually reaches this line" is NOT
	// independently verified here. This check sits after pgxpool.New and Ping,
	// so no unit test that lacks a database can observe it running. Proving the
	// call happens on the real startup path belongs to a deployment smoke test.
	if missing := deps.MissingRequired(); len(missing) > 0 {
		return nil, nil, fmt.Errorf("gateway composition incomplete, these dependencies were constructed by nobody: %s "+
			"(wire them here, or declare them in optionalGatewayDeps with the reason they may stay unset)",
			strings.Join(missing, ", "))
	}
	router, err := NewGatewayAPIRouterWithDependencies(cfg.ServiceName, cfg.Version, deps)
	if err != nil {
		return nil, nil, err
	}
	return router, recoveryPump, nil
}

// buildEvidenceRuntime composes the GA Task 0D semantic evidence runtime behind
// /v1/runtime/locate and /v1/runtime/read, or returns a nil EvidenceService when
// the deployment did not configure one.
//
// The four config fields are ALL-OR-NOTHING and checked here rather than by the
// wiring guard, because a string, a []byte and a document are configuration
// VALUES that reflection cannot judge unset (wiring.Inspects skips them by
// design). A partial set is a startup error, on the AGENTNEXUS_APPROVAL_CHANNEL
// precedent: an operator who supplied a staging root but no content key must be
// told at startup, not left with a plane that accepts every locate and fails it.
//
// WHAT THIS ACTUALLY DELIVERS TODAY — read before assuming the plane works:
//
//   - ContentSource is PendingContentSource. There is no resolver from a source
//     binding's private SourceRef to a connector manifest, customer binding,
//     resource/operation and credential ref; that is task B3. Every fetch fails
//     closed with 503 evidence_unavailable. Nothing fabricates records.
//   - The private semantic registry is now POPULATED, from the deployment's
//     EvidenceSourceCatalog (evidence/catalog.go). A declared data class
//     resolves, is authorized against the sealed organization snapshot, and
//     reaches the content source above — where it meets the 503 named there. An
//     UNDECLARED data class still denies at not_resolvable, which is correct
//     and is not something a catalog may relax. This was the gap the B6 note
//     recorded here: Service.RegisterSourceBinding had no caller, so the
//     registry was empty and locate answered 403 evidence_denied for
//     everything, on a surface that reported healthy to every probe.
//   - No ObservationSigner is wired, so verification-purpose reads fail closed
//     — and that is only the FIRST of two independent gaps. Migration 000015
//     added the authority columns and PostgresStore now round-trips them, so a
//     catalog entry CAN declare an observation authority and get past
//     observation_authority_undeclared. It still cannot mint: the receipt needs
//     a signer, and behind it worker.ObservationProducer (result.go, Task 7)
//     has no implementation at all. A green locate says nothing about
//     verification; the two paths must be tested separately.
//
// The ObjectStore is FileObjectStore: durable, atomic and traversal-guarded, but
// NODE-LOCAL. With more than one gateway-api replica a handle staged by one
// replica is unreadable on another — the read fails authenticated decryption and
// reports 503. That is fail-closed, not a leak, but it makes this composition
// single-node until a shared ObjectStore exists.
func buildEvidenceRuntime(ctx context.Context, pool *pgxpool.Pool, cfg PostgresGatewayConfig, auditSink *PostgresBrowserAuditSink, snapshots policy.SnapshotSource, actionStore *actions.PostgresStore) (EvidenceService, error) {
	service, err := composeEvidenceRuntime(pool, cfg, auditSink, snapshots, actionStore)
	if err != nil || service == nil {
		return nil, err
	}
	// Populate the private semantic registry. This is the caller
	// Service.RegisterSourceBinding never had; without it the composition above
	// is a plane that denies every locate at not_resolvable.
	//
	// It runs at startup and FAILS THE COMPOSITION on any error. A catalog that
	// names a connector binding the tenant does not have, or a write capability,
	// or an authorization pair the neutral policy does not grant, is a
	// deployment that would answer 403 forever for the data class it thought it
	// had configured — so the router refuses to exist rather than serve that.
	// Applying is idempotent (see ApplySourceCatalog), so a restart re-applies
	// the same rows without disturbing a live handle.
	registered, err := evidence.ApplySourceCatalog(ctx, service, postgresConnectorSourceResolver{pool: pool}, cfg.EvidenceSourceCatalog)
	if err != nil {
		return nil, fmt.Errorf("evidence source catalog: %w", err)
	}
	slog.InfoContext(ctx, "evidence.source_catalog_applied", slog.Int("sources", len(registered)))
	return service, nil
}

// composeEvidenceRuntime builds the service over its six ports, or returns the
// interface's own nil when the deployment configured nothing. It is split from
// buildEvidenceRuntime so the port composition is testable without a database:
// applying a catalog necessarily writes through PostgresStore, so the two
// concerns cannot share one test.
func composeEvidenceRuntime(pool *pgxpool.Pool, cfg PostgresGatewayConfig, auditSink *PostgresBrowserAuditSink, snapshots policy.SnapshotSource, actionStore *actions.PostgresStore) (*evidence.Service, error) {
	var missing []string
	for _, entry := range []struct {
		name string
		set  bool
	}{
		{"EvidenceObjectRoot", cfg.EvidenceObjectRoot != ""},
		{"EvidenceContentKeyRef", cfg.EvidenceContentKeyRef != ""},
		{"EvidenceContentKey", len(cfg.EvidenceContentKey) > 0},
		{"EvidenceSourceCatalog", cfg.EvidenceSourceCatalog.Declared()},
	} {
		if !entry.set {
			missing = append(missing, entry.name)
		}
	}
	switch len(missing) {
	case 4:
		// Nothing configured: the historical shape. Return the interface's own
		// nil rather than a typed nil pointer, which would be non-nil to the
		// dependency check and register endpoints over a nil service.
		return nil, nil
	case 0:
	default:
		return nil, fmt.Errorf("evidence runtime configuration incomplete, missing: %s "+
			"(supply all four, or none to leave /v1/runtime/locate and /v1/runtime/read unregistered)",
			strings.Join(missing, ", "))
	}
	objects, err := evidence.NewFileObjectStore(cfg.EvidenceObjectRoot)
	if err != nil {
		return nil, fmt.Errorf("evidence object store: %w", err)
	}
	keys, err := evidence.NewConfiguredKeyProvider(cfg.EvidenceContentKeyRef, cfg.EvidenceContentKey)
	if err != nil {
		return nil, fmt.Errorf("evidence content key: %w", err)
	}
	return evidence.NewService(
		evidence.NewPostgresStore(pool),
		objects,
		keys,
		evidence.NewPendingContentSource(),
		// The same neutral capability policy the rest of the gateway decides on;
		// the evidence plane never builds a parallel authorization path.
		policy.NewCapabilityEvaluator(snapshots, policy.WithSnapshotIntegrityObserver(snapshotIntegrityLogger{})),
		evidenceAuditSink{sink: auditSink},
		evidence.WithActionBindingVerifier(actions.NewBindingVerifier(actionStore)),
	), nil
}

// evidenceAuditSink adapts the hash-chained audit ledger to the evidence
// AuditSink port. The evidence plane makes this append MANDATORY on both allow
// paths — no handle is issued and no bytes are served without a recorded
// lineage head — so a failure here is a fail-closed 503, never silent egress.
type evidenceAuditSink struct{ sink *PostgresBrowserAuditSink }

func (s evidenceAuditSink) AppendEvidenceAudit(ctx context.Context, event evidence.AuditEvent) (string, error) {
	if s.sink == nil {
		return "", errors.New("evidence audit sink is not wired")
	}
	return s.sink.AppendEvidenceLineageAudit(ctx, event)
}

// buildAuditSigner constructs the GA Task 0G audit signer and registers its
// public half in the signing-key registry so the offline verifier can resolve
// it. A configured key is used as-is; otherwise a local ed25519 key is generated
// (dev/default). Registration is idempotent (upsert) - a redeploy re-registers
// the same public key without disturbing prior events.
func buildAuditSigner(ctx context.Context, pool *pgxpool.Pool, cfg PostgresGatewayConfig) (audit.AuditSigner, error) {
	keyID := cfg.AuditSigningKeyID
	key := cfg.AuditSigningKey
	if len(key) != ed25519.PrivateKeySize {
		// Fail closed: no silent ephemeral key. Without a stable key there is no
		// stable identity to pin as the verifier's trust anchor.
		if !cfg.AllowEphemeralAuditKey {
			return nil, errors.New("no stable audit signing key configured: set AuditSigningKey/AuditSigningKeyID for production, or AllowEphemeralAuditKey for a dev-only ephemeral key")
		}
		generatedPub, generatedKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		key = generatedKey
		if keyID == "" {
			keyID = "audit-ephemeral-" + hexPrefix(generatedPub)
		}
	}
	if keyID == "" {
		keyID = "audit-configured"
	}
	signer, err := audit.NewEd25519AuditSigner(keyID, key)
	if err != nil {
		return nil, err
	}
	if _, err := db.New(pool).UpsertAuditSigningKey(ctx, db.UpsertAuditSigningKeyParams{
		KeyID: signer.KeyID(), Algorithm: audit.SignatureAlgorithmEd25519, PublicKey: signer.PublicKey(),
	}); err != nil {
		return nil, err
	}
	return signer, nil
}

// hexPrefix returns a short stable hex tag of a public key for a default key id.
func hexPrefix(pub ed25519.PublicKey) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 16)
	for _, b := range pub[:8] {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}

// postgresSigningKeyResolver resolves connector/audit signing keys from the
// signing-key registry for the receipt verifier. ResolveKey has no context by
// contract, so it uses a short bounded background lookup; a miss or error fails
// closed (the receipt is rejected). A revoked key resolves with revoked status.
type postgresSigningKeyResolver struct{ pool *pgxpool.Pool }

func (r postgresSigningKeyResolver) ResolveKey(keyID string) (sdkaudit.SigningKey, bool) {
	if r.pool == nil || keyID == "" {
		return sdkaudit.SigningKey{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	row, err := db.New(r.pool).GetAuditSigningKey(ctx, keyID)
	if err != nil {
		return sdkaudit.SigningKey{}, false
	}
	status := sdkaudit.KeyActive
	if row.Status == string(sdkaudit.KeyRevoked) {
		status = sdkaudit.KeyRevoked
	}
	key := sdkaudit.SigningKey{KeyID: row.KeyID, Algorithm: row.Algorithm, PublicKey: row.PublicKey, Status: status}
	if row.CreatedAt.Valid {
		key.CreatedAt = row.CreatedAt.Time
	}
	if row.RevokedAt.Valid {
		key.RevokedAt = row.RevokedAt.Time
	}
	return key, true
}

// actionAuditSink adapts the hash-chained audit ledger to the actions audit
// port. Action-transition lineage rides the INTERNAL audit vocabulary (like the
// approval-transmission lineage); Task 0G chains and signs the events.
type actionAuditSink struct{ sink *PostgresBrowserAuditSink }

func (s actionAuditSink) AppendActionAudit(ctx context.Context, event actions.AuditEvent) (string, error) {
	if s.sink == nil {
		return "", errors.New("action audit sink is not wired")
	}
	return s.sink.AppendActionTransitionAudit(ctx, event)
}

// actionEvidenceConsumer adapts the approvaltransport ConsumeEvidence store path
// to the actions EvidenceConsumer port: it consumes the approval authority's
// validated decision EXACTLY ONCE (the consumed_at one-shot gate) when Task 0F
// mints the grant.
type actionEvidenceConsumer struct{ store *approvaltransport.PostgresStore }

func (a actionEvidenceConsumer) ConsumeApprovalEvidence(ctx context.Context, tenantRef, planRef string, at time.Time) (actions.ConsumedEvidence, error) {
	consumed, err := a.store.ConsumeEvidence(ctx, tenantRef, planRef, at)
	if err != nil {
		switch {
		case errors.Is(err, approvaltransport.ErrEvidenceConsumed):
			return actions.ConsumedEvidence{}, actions.ErrEvidenceConsumed
		case errors.Is(err, approvaltransport.ErrNotFound):
			return actions.ConsumedEvidence{}, actions.ErrNotFound
		case errors.Is(err, approvaltransport.ErrTransmissionRevoked):
			return actions.ConsumedEvidence{}, actions.ErrEvidenceRejected
		}
		return actions.ConsumedEvidence{}, actions.ErrUnavailable
	}
	return actions.ConsumedEvidence{
		ApprovalRef:   consumed.ApprovalRef,
		PlanRef:       consumed.PlanRef,
		Capability:    consumed.Capability,
		ParameterHash: consumed.ParameterHash,
		Decision:      consumed.Decision,
	}, nil
}

// approvalTransportAuditSink adapts the hash-chained audit ledger to the
// approvaltransport audit port. The transmission lineage actions ride the
// INTERNAL audit vocabulary (like the browser-session lineage) — the public
// /v1/audit/evidence AuditEvidenceAction enum stays frozen; Task 0G chains
// the events further.
type approvalTransportAuditSink struct{ sink *PostgresBrowserAuditSink }

func (s approvalTransportAuditSink) AppendApprovalAudit(ctx context.Context, event approvaltransport.AuditEvent) (string, error) {
	if s.sink == nil {
		return "", errors.New("approval audit sink is not wired")
	}
	return s.sink.AppendApprovalTransmissionAudit(ctx, event)
}
