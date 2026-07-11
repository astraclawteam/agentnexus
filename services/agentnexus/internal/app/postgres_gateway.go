package app

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/browserauth"
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
	ApprovalFactsVerifier       ChangeFactsVerifier
	RequestTimeout              time.Duration
}

func NewPostgresGatewayRouter(ctx context.Context, pool *pgxpool.Pool, cfg PostgresGatewayConfig) (http.Handler, error) {
	if pool == nil || ctx == nil || cfg.ServiceName == "" || cfg.Version == "" || cfg.ApprovalFactsVerifier == nil {
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
	authorizationPolicy := NewPostgresAtlasPolicySource(pool)
	ticketActors := NewPostgresTicketActorAuthenticator(cfg.OIDC.EnterpriseID, pool, time.Now)
	grantStore := NewPostgresGrantStore(pool)
	auditSink := NewPostgresBrowserAuditSink(pool)
	grantService := tickets.NewService(grantStore, tickets.WithGrantAuthorizer(NewScopedGrantAuthorizer(grantStore, policy.NewAgentAtlasEvaluator(authorizationPolicy))))
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
		TicketActors:            ticketActors,
		ApprovalSource:          NewPostgresApprovalSource(pool),
		ApprovalStore:           NewPostgresApprovalStore(pool),
		ApprovalFactsVerifier:   cfg.ApprovalFactsVerifier,
		Grants:                  grantService,
		RequestTimeout:          cfg.RequestTimeout,
	})
}
