package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
)

// Resolution failures. Every one of them is a REFUSAL to execute: the worker
// never guesses a binding, never picks one of several, and never runs an
// operation whose coordinates it could not derive from server-side truth.
var (
	// ErrBindingNotFound marks a tenant + capability with no customer binding.
	ErrBindingNotFound = errors.New("no connector binding for this tenant and capability")
	// ErrBindingAmbiguous marks a tenant + capability that resolves to MORE than
	// one binding. Picking one would execute a real side effect against an
	// arbitrary customer system, so this is a refusal rather than a choice.
	ErrBindingAmbiguous = errors.New("connector binding is ambiguous for this tenant and capability")
	// ErrBindingUnresolvable marks a binding that exists but cannot be turned
	// into runnable coordinates: an unimportable pack, an invalid binding
	// document, a digest that does not match the pinned product, a capability
	// with no resource mapping, or an absent/ambiguous credential reference.
	ErrBindingUnresolvable = errors.New("connector binding cannot be resolved to a runnable operation")
	// ErrNoHostFactory marks a resolver with no HostFactory configured. See
	// HostFactory for why this is a deployment fact rather than a bug.
	ErrNoHostFactory = errors.New("no connector host factory is configured for this deployment")
)

// PermanentResolutionFailure reports whether a BindingResolver failure can NEVER
// be resolved by redelivering the SAME dispatch. It is the split the dispatcher
// needs: a permanent failure must fail the Action, a transient one must nak.
//
// PERMANENT is exactly the three refusal sentinels above, and the taxonomy is
// deliberately not wider than what this resolver can actually produce:
//
//   - ErrBindingNotFound — the tenant has no binding for the capability;
//   - ErrBindingAmbiguous — more than one binding declares it;
//   - ErrBindingUnresolvable — a binding exists but cannot become runnable
//     coordinates (unimportable pack, invalid binding document, digest that does
//     not match the pinned product, undeclared capability, unmapped resource,
//     absent/ambiguous credential reference).
//
// Every one of those is a fact about STORED customer data. Redelivery re-reads
// the same rows and re-derives the same refusal, so retrying only burns delivery
// attempts; the fix is a customer or operator changing a binding, and that change
// arrives as a NEW dispatch, not as a redelivery of this one.
//
// TRANSIENT is everything else, and that is the safe default on purpose: a raw
// store error from the binding query, a context cancellation during shutdown, and
// any future error this function has not been taught. Mis-calling a transient
// failure permanent LOSES an Action that would have succeeded; mis-calling a
// permanent failure transient only costs redeliveries. So an unrecognised error
// naks.
//
// ErrNotReady and ErrNoHostFactory are TRANSIENT even though they are certain to
// recur: they are deployment facts (no pool, no host wiring — see HostFactory),
// not facts about the customer's binding. The Action is perfectly executable and
// the deployment is not; failing it would destroy a valid Action to report an
// outage. They are the honest-503 class, and they resolve by deploying, without
// anyone touching the Action.
//
// That classification is only safe because such a worker never reaches the
// stream: a resolver that is structurally unable to produce a runnable operation
// reports it through PostgresBindingResolver.CheckReady, the readiness gate parks
// the worker, and no intent is ever pulled to nak. Read that method before
// reclassifying either sentinel — the two halves are one decision, and moving
// either one alone reintroduces a poison loop or loses executable Actions.
//
// A transient marker WINS when an error somehow carries both, for the same
// asymmetry: never fabricate a terminal failure while an outage is in evidence.
func PermanentResolutionFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNotReady) || errors.Is(err, ErrNoHostFactory) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, ErrBindingNotFound) ||
		errors.Is(err, ErrBindingAmbiguous) ||
		errors.Is(err, ErrBindingUnresolvable)
}

// ResolutionRequest is the server-side truth a HostFactory receives for one
// resolution. Every field is derived from the signed pack and the customer
// binding; nothing in it came from an Agent.
type ResolutionRequest struct {
	TenantRef  string
	Capability string
	// Pack is the imported, signature-verified Product Pack, and Binding is the
	// customer binding pinned to its exact content digest.
	Pack    connector.ProductPack
	Binding connector.CustomerBinding
	// Resource is the customer resource the binding maps this capability onto.
	Resource string
	// OperationAction is "read" or "write", derived from the pack capability's
	// declared Effect — never from the caller.
	OperationAction string
}

// HostBinding is what a HostFactory produces: the isolated host bound to one
// connector instance, plus the family-specific operation verb to invoke.
type HostBinding struct {
	Host HostRunner
	// Operation is the family-specific verb ("list", "select", "put"). It is
	// deliberately the FACTORY's to supply, not the resolver's — see HostFactory.
	Operation string
}

// HostFactory builds the isolated host for one resolved connector instance.
//
// It exists as a port because two facts a runnable operation needs are NOT
// declared by the frozen GA schemas, and this resolver refuses to invent them:
//
//   - Which connector FAMILY (http/openapi, db-readonly, file/s3, webhook) a
//     product belongs to. Neither ProductPack nor CustomerBinding says. The pack
//     schema is closed-world (additionalProperties:false) and contract-frozen, so
//     adding a family field there is a contract change, not a refactor.
//   - The family-specific OPERATION verb for a capability. The binding maps a
//     capability to a Resource (ResourceMappings) but never to an operation.
//
// Everything the schemas DO declare — the pinned pack, the customer binding, the
// resource, the read/write action and the credential reference — this resolver
// derives itself and hands over above. A factory therefore cannot widen the
// resolution; it can only supply the two undeclared facts and the wiring
// (family adapter, injected client, secret broker) that turns them into a host.
//
// No implementation ships in this build. internal/connectors/runtime has all
// four family adapters, but each needs an injected client (HTTPClient, DBClient,
// ObjectStore, WebhookSender) and NONE of those has a production implementation
// — they exist only as fakes in the conformance test. A resolver with no factory
// therefore fails closed with ErrNoHostFactory, on the PendingContentSource and
// PendingDeliveryChannel precedent: an honest 503 with a named reason, never a
// fabricated host and never a pass-stub.
type HostFactory interface {
	HostFor(ctx context.Context, req ResolutionRequest) (HostBinding, error)
}

// PostgresBindingResolver is the concrete private BindingResolver over the
// signed connector_products / connector_bindings tables of migration 000012.
//
// It NEVER accepts a connector id from a caller: the only inputs are the tenant
// of the server-authored dispatch message and the semantic capability of the
// stored Action. Everything else is read from the customer's own binding and the
// signed product it pins.
type PostgresBindingResolver struct {
	pool  *pgxpool.Pool
	hosts HostFactory
}

// The port this type exists to fill. app.NewPostgresWorkerSeams now constructs
// this resolver into a worker.Config, so the assertion is no longer the only
// thing type-checking the conformance; it is kept because it states the intent
// at the definition rather than at a composition root in another package.
var _ BindingResolver = (*PostgresBindingResolver)(nil)

// And the optional readiness probe, which is what keeps a resolver that can
// resolve nothing off the dispatch stream. Stated here because the conformance
// is load-bearing and satisfied structurally: a renamed or dropped CheckReady
// would otherwise leave the worker silently "ready" again.
var _ ResolverReadiness = (*PostgresBindingResolver)(nil)

// NewPostgresBindingResolver builds the resolver. A nil HostFactory is allowed
// and is the shipped state of this build: resolution then fails closed at
// ErrNoHostFactory AFTER doing all the real work, so the failure names the
// missing host wiring rather than masking a bad binding behind it. Such a
// resolver reports NOT-READY (CheckReady), which is what keeps a worker holding
// it off the dispatch stream instead of naking every intent it pulls.
func NewPostgresBindingResolver(pool *pgxpool.Pool, hosts HostFactory) *PostgresBindingResolver {
	return &PostgresBindingResolver{pool: pool, hosts: hosts}
}

// CheckReady reports whether this resolver could resolve ANY dispatch onto a
// runnable operation in this deployment. It is the resolver's half of the
// readiness gate, and it exists to close a poison loop BEFORE one can form.
//
// WHY THIS, AND NOT A PERMANENT ErrNoHostFactory. A resolver with no HostFactory
// does the entire resolution and then refuses, and that refusal is TRANSIENT
// (see PermanentResolutionFailure) because it is a fact about the DEPLOYMENT,
// not about the customer's binding: the Action is perfectly executable and the
// process is not. Calling it permanent would fail durable, valid Actions to
// report an outage — and would do it for exactly the failure a deployment can
// fix while the process is up, which is the premise of the readiness gate.
// Leaving it transient with nothing else changed is the other bad end: the
// worker naks every intent it pulls, forever, burning delivery attempts on
// Actions it will never run — the shape failUnresolvedBinding was written to end.
//
// The two are reconciled by never pulling the intent. The gate already exists;
// it simply did not cover this seam, because Worker.CheckReady sees a non-nil
// BindingResolver and cannot tell a resolver that can run from one that will
// refuse everything. This probe is that missing coverage, and it makes the nil
// HostFactory behave exactly like the nil ObservationProducer beside it: an
// honest 503 with a named reason, a gate that parks instead of crash-looping,
// and a deployment that starts serving the moment the seam is wired — with no
// Action ever pulled to nak. No fabricated host, no default factory, no
// pass-stub: the missing wiring is reported, never invented.
//
// It is deliberately STRUCTURAL (is a pool present, is a factory present) and
// does no I/O. A store outage is a transient RESOLUTION failure that must nak and
// retry; making it a readiness verdict would park a healthy worker on a blip and
// stop it consuming for as long as the probe kept failing.
func (r *PostgresBindingResolver) CheckReady(context.Context) error {
	switch {
	case r == nil || r.pool == nil:
		return errors.Join(ErrNotReady, errors.New("binding resolver has no database pool"))
	case r.hosts == nil:
		return errors.Join(ErrNotReady, ErrNoHostFactory)
	}
	return nil
}

// Resolve privately resolves one tenant + capability onto a runnable connector
// operation. Every failure path is a refusal; none of them invents a binding.
func (r *PostgresBindingResolver) Resolve(ctx context.Context, tenantRef, capability string) (ResolvedBinding, error) {
	if r == nil || r.pool == nil {
		return ResolvedBinding{}, errors.Join(ErrNotReady, errors.New("binding resolver has no database pool"))
	}
	if tenantRef == "" || capability == "" {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable, errors.New("resolution requires a tenant and a capability"))
	}

	rows, err := db.New(r.pool).ListConnectorBindingsForCapability(ctx, db.ListConnectorBindingsForCapabilityParams{
		TenantID:   tenantRef,
		Capability: capability,
	})
	if err != nil {
		return ResolvedBinding{}, err // a store outage is transient; the caller naks
	}
	switch len(rows) {
	case 0:
		return ResolvedBinding{}, ErrBindingNotFound
	case 1:
	default:
		// Deliberately no topology in the message: how many bindings a tenant has
		// is internal, and the count is enough for an operator with database
		// access to investigate.
		return ResolvedBinding{}, fmt.Errorf("%w: %d bindings declare it", ErrBindingAmbiguous, len(rows))
	}
	row := rows[0]

	// Import through the SDK, never by trusting the table. Migration 000012 says
	// so in its own comments: the CHECK constraints there are a partial denylist,
	// and the closed-world guarantee (closed Go struct + closed JSON Schema with
	// additionalProperties:false, plus signature verification) lives in the SDK.
	pack, err := connector.ImportProductionPack(row.PackDocument)
	if err != nil {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable, fmt.Errorf("import product pack: %w", err))
	}
	binding, err := connector.ParseBinding(row.BindingDocument)
	if err != nil {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable, fmt.Errorf("parse customer binding: %w", err))
	}
	if err := connector.ValidateBinding(binding); err != nil {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable, fmt.Errorf("validate customer binding: %w", err))
	}

	// Re-bind the digest from the DOCUMENTS. The foreign key already joins on
	// (product_key, version, digest), but that constrains the table's own columns
	// to each other, not the documents those columns claim to describe: a row
	// whose binding_document pins a different digest than its product_digest
	// column satisfies the FK perfectly. The documents are the authority, so a
	// digest-swapped pack is refused here, before any host exists.
	if binding.Product.Digest != pack.Digest {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable,
			errors.New("customer binding pins a different product digest than the pack it loaded"))
	}

	declared, ok := packCapability(pack, capability)
	if !ok {
		// The SQL predicate matched the capability inside pack_document, so a miss
		// here means the stored JSON and the imported pack disagree.
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable,
			errors.New("the pinned pack does not declare the requested capability"))
	}
	if !declared.Effect.Valid() {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable,
			errors.New("the declared capability has no valid read/write effect"))
	}
	resource, ok := mappedResource(binding, capability)
	if !ok {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable,
			errors.New("the customer binding maps no resource for this capability"))
	}
	credentialRef, err := credentialReference(binding)
	if err != nil {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable, err)
	}

	request := ResolutionRequest{
		TenantRef:       tenantRef,
		Capability:      capability,
		Pack:            pack,
		Binding:         binding,
		Resource:        resource,
		OperationAction: string(declared.Effect),
	}
	if r.hosts == nil {
		return ResolvedBinding{}, ErrNoHostFactory
	}
	hostBinding, err := r.hosts.HostFor(ctx, request)
	if err != nil {
		return ResolvedBinding{}, err
	}
	if hostBinding.Host == nil {
		return ResolvedBinding{}, errors.Join(ErrNotReady, errors.New("host factory returned no host runner"))
	}
	if hostBinding.Operation == "" {
		return ResolvedBinding{}, errors.Join(ErrBindingUnresolvable,
			errors.New("host factory returned no operation for this capability"))
	}

	return ResolvedBinding{
		Host:            hostBinding.Host,
		Resource:        resource,
		Operation:       hostBinding.Operation,
		OperationAction: request.OperationAction,
		CredentialRef:   credentialRef,
		// The private connector instance identity, for internal audit only. The
		// binding key is the customer's own name for this instance and must never
		// reach an Agent-facing surface.
		ConnectorRef: row.BindingKey,
	}, nil
}

// packCapability finds a declared capability by exact name.
func packCapability(pack connector.ProductPack, name string) (connector.Capability, bool) {
	for _, c := range pack.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return connector.Capability{}, false
}

// mappedResource returns the customer resource this binding maps the capability
// onto. A capability mapped more than once is treated as unmapped: two resources
// for one capability is the same ambiguity as two bindings, one level down, and
// taking the first would silently pick a customer table by declaration order.
func mappedResource(binding connector.CustomerBinding, capability string) (string, bool) {
	resource := ""
	for _, m := range binding.ResourceMappings {
		if m.Capability != capability {
			continue
		}
		if resource != "" && m.Resource != resource {
			return "", false
		}
		resource = m.Resource
	}
	return resource, resource != ""
}

// credentialReference returns the binding's single opaque secret REFERENCE.
//
// It is a reference, never a value: migration 000012 and the SDK both reject
// inline secret material in a binding, and the host redeems this reference for
// an operation-scoped Secret Handle.
//
// A binding with several secrets is refused rather than resolved to the first.
// Which credential an operation runs under is an authorization fact, and picking
// one by declaration order would silently bind a real side effect to whichever
// secret happened to be listed first. Selecting among several needs a declared
// rule, and no schema declares one.
func credentialReference(binding connector.CustomerBinding) (string, error) {
	switch len(binding.Secrets) {
	case 0:
		// Legitimate: a connector reachable without a credential. The runtime
		// skips secret acquisition entirely on an empty reference.
		return "", nil
	case 1:
		if binding.Secrets[0].Ref == "" {
			return "", errors.New("the customer binding declares a secret with no reference")
		}
		return binding.Secrets[0].Ref, nil
	default:
		return "", fmt.Errorf("the customer binding declares %d secrets and nothing says which one this capability runs under", len(binding.Secrets))
	}
}
