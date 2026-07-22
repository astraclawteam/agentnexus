package app

import (
	"context"
	"errors"
	"fmt"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	db "github.com/astraclawteam/agentnexus/services/agentnexus/db/generated"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
	"github.com/jackc/pgx/v5/pgxpool"
)

// postgresConnectorSourceResolver resolves an evidence source catalog entry's
// connector reference against the signed connector_products /
// connector_bindings tables of migration 000012 — the same server-side truth
// worker.PostgresBindingResolver executes against, read here for a different
// question.
//
// The two resolvers are deliberately NOT shared. The worker resolves a tenant +
// capability all the way to a RUNNABLE operation (resource mapping, credential
// reference, isolated host) and refuses without a HostFactory, which no build
// supplies. Registration asks something strictly weaker and answerable today:
// does this named binding exist, is it pinned to a signed pack, and does that
// pack declare this capability as a READ? Reusing the worker's Resolve here
// would fail every registration at ErrNoHostFactory for a host registration
// never needs, and mapping/credential resolution is the execution plane's to
// own at fetch time — doing it twice would create a second authority free to
// disagree with the first.
type postgresConnectorSourceResolver struct{ pool *pgxpool.Pool }

// The port this type exists to fill.
var _ evidence.ConnectorSourceResolver = postgresConnectorSourceResolver{}

// ResolveConnectorSource derives the private SourceRef of one catalog entry, or
// refuses. Every refusal is a startup failure that names a fact about stored
// customer data, so it is fixed by correcting the catalog or the binding — never
// by retrying.
func (r postgresConnectorSourceResolver) ResolveConnectorSource(ctx context.Context, ref evidence.ConnectorSourceRef) (string, error) {
	if r.pool == nil {
		return "", errors.New("no database pool to resolve connector bindings through")
	}
	if err := evidence.ValidateConnectorRef(evidence.CatalogConnectorRef{
		BindingKey: ref.BindingKey, Capability: ref.Capability,
	}); err != nil {
		return "", err
	}

	// Every binding of this tenant whose PINNED pack declares the capability.
	rows, err := db.New(r.pool).ListConnectorBindingsForCapability(ctx, db.ListConnectorBindingsForCapabilityParams{
		TenantID:   ref.TenantRef,
		Capability: ref.Capability,
	})
	if err != nil {
		return "", fmt.Errorf("read connector bindings: %w", err)
	}
	// (tenant_id, binding_key) is the primary key of connector_bindings, so the
	// match is unique by construction; the loop selects rather than disambiguates.
	var row db.ListConnectorBindingsForCapabilityRow
	found := false
	for _, candidate := range rows {
		if candidate.BindingKey == ref.BindingKey {
			row, found = candidate, true
			break
		}
	}
	if !found {
		// Deliberately no topology and no counts: which bindings this tenant has
		// is internal, and the catalog entry the caller already holds names the
		// binding key it asked for.
		return "", errors.New("no connector binding of this tenant declares the named capability under that binding key")
	}
	return connectorSourceFromDocuments(ref, row.PackDocument, row.BindingDocument)
}

// connectorSourceFromDocuments is the half of the resolution that judges the two
// stored DOCUMENTS rather than the table that holds them. It is separated from
// the query above so every refusal it can produce is testable without a
// database; what stays behind the query is one statement byte-identical to the
// one worker.PostgresBindingResolver already exercises against real PostgreSQL.
func connectorSourceFromDocuments(ref evidence.ConnectorSourceRef, packDocument, bindingDocument []byte) (string, error) {
	// Import through the SDK, never by trusting the table — migration 000012
	// says so in its own comments: its CHECK constraints are a partial denylist
	// and the closed-world guarantee lives in the SDK.
	pack, err := connector.ImportProductionPack(packDocument)
	if err != nil {
		return "", fmt.Errorf("import product pack: %w", err)
	}
	binding, err := connector.ParseBinding(bindingDocument)
	if err != nil {
		return "", fmt.Errorf("parse customer binding: %w", err)
	}
	if err := connector.ValidateBinding(binding); err != nil {
		return "", fmt.Errorf("validate customer binding: %w", err)
	}
	// Re-bind the digest from the DOCUMENTS. The foreign key constrains the
	// table's own columns to each other, not the documents those columns claim
	// to describe, so a binding_document pinning a different digest than its
	// product_digest column satisfies the FK perfectly.
	if binding.Product.Digest != pack.Digest {
		return "", errors.New("the customer binding pins a different product digest than the pack it loaded")
	}

	declared, ok := packReadCapability(pack, ref.Capability)
	if !ok {
		// The SQL predicate matched the capability inside pack_document, so a
		// miss here means the stored JSON and the imported pack disagree.
		return "", errors.New("the pinned pack does not declare the requested capability")
	}
	if declared.Effect != connector.EffectRead {
		// The evidence plane OBSERVES. Registering a data class onto a write
		// capability would point locate at a side-effecting operation, so this
		// is a refusal rather than a warning.
		return "", fmt.Errorf("the capability is declared with the %q effect; evidence sources must be read capabilities", declared.Effect)
	}
	return ref.SourceRef(), nil
}

// packReadCapability finds a declared capability by exact name.
func packReadCapability(pack connector.ProductPack, name string) (connector.Capability, bool) {
	for _, c := range pack.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return connector.Capability{}, false
}
