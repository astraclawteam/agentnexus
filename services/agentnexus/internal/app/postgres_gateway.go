package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/netip"
	"time"

	sdkaudit "github.com/astraclawteam/agentnexus/sdk/go/audit"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
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
}

func NewPostgresGatewayRouter(ctx context.Context, pool *pgxpool.Pool, cfg PostgresGatewayConfig) (http.Handler, error) {
	if pool == nil || ctx == nil || cfg.ServiceName == "" || cfg.Version == "" {
		return nil, errors.New("postgres gateway dependencies incomplete")
	}
	upstream, err := browserauth.NewEnterpriseOIDC(ctx, cfg.OIDC)
	if err != nil {
		return nil, err
	}
	directory := NewPostgresBrowserDirectory(pool)
	authorizeRateLimiter, err := browserauth.NewPostgresAuthorizeRateLimiter(pool, cfg.AuthorizeRateLimitPerMinute, time.Now)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	auditSink := NewPostgresBrowserAuditSink(pool, WithAuditSigner(auditSigner))
	grantService := tickets.NewService(grantStore, tickets.WithGrantAuthorizer(NewScopedGrantAuthorizer(grantStore, policy.NewCapabilityEvaluator(authorizationPolicy, policy.WithSnapshotIntegrityObserver(snapshotIntegrityLogger{})))))
	var approvalTransmission ApprovalTransmissionService
	if cfg.ApprovalChannel != nil {
		transmissionService, err := approvaltransport.NewService(approvaltransport.NewPostgresStore(pool), cfg.ApprovalChannel, approvalTransportAuditSink{sink: auditSink})
		if err != nil {
			return nil, err
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
	actionService, err := actions.NewService(actionStore, actionAuditSink{sink: auditSink},
		actions.WithEvidenceConsumer(actionEvidenceConsumer{store: approvaltransport.NewPostgresStore(pool)}),
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(postgresSigningKeyResolver{pool: pool})))
	if err != nil {
		return nil, err
	}
	// The GA Task 0F ActionBindingVerifier implements the evidence
	// ActionBindingVerifier seam; it type-checks here and is ready to wire into
	// the evidence service's WithActionBindingVerifier once the evidence RUNTIME
	// is constructed in production (its object/key/content/decider ports are not
	// part of PostgresGatewayConfig yet).
	var _ evidence.ActionBindingVerifier = actions.NewBindingVerifier(actionStore)
	return NewGatewayAPIRouterWithDependencies(cfg.ServiceName, cfg.Version, BrowserAuthDependencies{
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
		RequestTimeout:          cfg.RequestTimeout,
	})
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
