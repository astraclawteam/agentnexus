package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/audit"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresWorkerConfig is the production dependency contract of the connector
// worker's Postgres-backed execution seams, the way PostgresGatewayConfig is for
// the browser gateway. Keeping the wiring here rather than in
// cmd/connector-worker lets the live PostgreSQL suite compose exactly what the
// binary composes.
//
// The signing key is the worker's own, NOT the gateway's. Both halves land in
// the same signing-key registry and both are ed25519 over a canonical
// pre-image, so one key could serve both processes — but they are separate
// deployments with separate blast radii, and a shared private key would mean
// revoking the gateway's audit key also stops every connector receipt verifying.
type PostgresWorkerConfig struct {
	// ReceiptSigningKeyID / ReceiptSigningKey sign the authoritative
	// ActionReceipt and the action-transition audit lineage. The key must be
	// STABLE: its public half is registered below so the actions
	// ReceiptVerifier resolves it, and receipts outlive the process. There is no
	// ephemeral fallback — see config.WorkerExecutionConfig.
	ReceiptSigningKeyID string
	ReceiptSigningKey   ed25519.PrivateKey
}

// NewPostgresWorkerSeams composes the connector worker's execution seams over
// PostgreSQL and returns them as the worker.Config fields they fill. Identity is
// left zero: it comes from the deployment's own configuration and this function
// has no business inventing it.
//
// WHAT THIS ACTUALLY DELIVERS TODAY — read before assuming the worker runs:
//
//   - Actions is the real Task 0F *actions.Service over the durable Postgres
//     store, with the signed ReceiptVerifier wired so only a receipt bearing a
//     verified signature by a registered, non-revoked key completes an Action.
//     No EvidenceConsumer, DecisionProviderVerifier or Publisher is wired,
//     deliberately: those serve the grant-minting and dispatch paths, and the
//     worker drives none of them — it only reads an Action, marks it executing,
//     ingests a receipt, or flags result_unknown.
//   - Signer is the real ed25519 signer, and its public half is registered here
//     so a receipt it produces verifies through the resolver above. The two are
//     composed together on purpose: a signer whose key is unregistered would
//     sign receipts the very same service then rejects.
//   - Resolver is the real PostgresBindingResolver over the signed
//     connector_products / connector_bindings tables — with a NIL HostFactory,
//     which is the shipped state of this build. It does all the real resolution
//     work (import the signed pack, validate the binding, re-bind the digest,
//     map the resource, pick the credential reference) and then fails closed at
//     ErrNoHostFactory, because no connector family adapter has a production
//     client. See worker.HostFactory for why that fact is not inventable here.
//
// That last point is load-bearing and must not be read past. ErrNoHostFactory is
// classified TRANSIENT (worker.PermanentResolutionFailure), so a worker that
// reached the stream with this resolver would nak every intent it pulled and
// burn the delivery attempts of durable Actions. What stops that today is that
// CheckReady still refuses on the nil ObservationProducer, which keeps the
// worker off the stream entirely. Whoever wires the ObservationProducer removes
// that protection: a HostFactory MUST be supplied in the same change.
//
// ObservationProducer is not composed here because it has no implementation
// anywhere in this build (Task 7). No stub, no pass-through, no fabricated
// receipt.
func NewPostgresWorkerSeams(ctx context.Context, pool *pgxpool.Pool, cfg PostgresWorkerConfig) (worker.Config, error) {
	if ctx == nil || pool == nil {
		return worker.Config{}, errors.New("connector worker seams require a context and a database pool")
	}
	signer, err := audit.NewEd25519AuditSigner(cfg.ReceiptSigningKeyID, cfg.ReceiptSigningKey)
	if err != nil {
		return worker.Config{}, err
	}
	// Register the public half BEFORE anything can sign with it. Registration is
	// idempotent (upsert), so a redeploy re-registers the same key without
	// disturbing prior events or receipts. This is also the first statement this
	// process runs against the database, so a DSN that points nowhere surfaces
	// here, at startup, with a reason — rather than at the first Action.
	if _, err := db.New(pool).UpsertAuditSigningKey(ctx, db.UpsertAuditSigningKeyParams{
		KeyID: signer.KeyID(), Algorithm: audit.SignatureAlgorithmEd25519, PublicKey: signer.PublicKey(),
	}); err != nil {
		return worker.Config{}, fmt.Errorf("register the connector worker receipt signing key: %w", err)
	}
	actionService, err := actions.NewService(
		actions.NewPostgresStore(pool),
		// The action-transition audit sink refuses to append an unsigned
		// high-risk event, so this signer is what makes the plane able to
		// transition at all, not merely able to sign receipts.
		actionAuditSink{sink: NewPostgresBrowserAuditSink(pool, WithAuditSigner(signer))},
		actions.WithReceiptVerifier(actions.NewSignedReceiptVerifier(postgresSigningKeyResolver{pool: pool})),
	)
	if err != nil {
		return worker.Config{}, err
	}
	return worker.Config{
		Actions:  actionService,
		Signer:   signer,
		Resolver: worker.NewPostgresBindingResolver(pool, nil),
	}, nil
}
