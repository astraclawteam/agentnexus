package app

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/approvaltransport"
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
	auditSink := NewPostgresBrowserAuditSink(pool)
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
	actionService, err := actions.NewService(actionStore, actionAuditSink{sink: auditSink},
		actions.WithEvidenceConsumer(actionEvidenceConsumer{store: approvaltransport.NewPostgresStore(pool)}))
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
