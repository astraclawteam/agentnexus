// Command demo-seed provisions the reproducible DEMO tenant the dev stack
// walks its main line against.
//
// WHY A COMMAND AND NOT SQL. Three of the five things this seeds cannot be
// written correctly by hand:
//
//   - The organization policy VERSION is sealed by a transaction that also
//     captures the snapshot (iam.Service.CreateOrgVersion -> PublishOrgVersion).
//     Inserting into org_versions directly would trip guard_org_policy_version_seal
//     and leave no snapshot rows behind.
//   - The connector product pack must satisfy connector.ImportProductionPack:
//     a closed-world schema, a content digest computed over the canonical
//     document, and a structurally well-formed signature block. Migration
//     000012's CHECK constraints are an explicit PARTIAL denylist and say so —
//     the closed-world guarantee is the SDK's, so the document is built and
//     imported through the SDK here rather than typed as JSON.
//   - The evidence source catalog is resolved against those same tables at
//     gateway-api startup, so an entry naming a capability the pack does not
//     declare as a READ is a startup failure, not a runtime one.
//
// Building all of it through the same packages the runtime reads it with makes
// an invalid seed impossible to commit.
//
// NO CREDENTIALS LIVE IN THE REPOSITORY. The case-ticket token, the evidence
// content key and the pack signing key are GENERATED on first run into an
// output directory and reused afterwards, following the pattern of
// deploy/compose/dev-auth-material/provision.sh. The content key in particular
// must be stable across restarts: it is referenced by every staged handle, so
// regenerating it would orphan previously staged content.
//
// Re-running is idempotent.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/evidence"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/iam"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The demo tenant. The tenant ref must equal the gateway's configured
// AGENTNEXUS_OIDC_ENTERPRISE_ID: evidenceHandler.begin rejects any principal
// whose TenantRef differs from it before the request reaches the service.
const defaultTenant = "agentnexus-dev"

// The connector product. A pack is the RESELLABLE, customer-agnostic half:
// it names Kingdee (金蝶) as the finance product it speaks to and declares one
// semantic read capability. It carries no endpoint, credential or field
// mapping — those are the binding's, below.
const (
	productKey     = "connector.kingdee_erp"
	productVersion = "1.0.0"
	readCapability = "erp.purchase_order.read"
)

// The customer binding. This half is customer-specific by design and is the
// only place topology appears. The customer here is fictional demo material.
const bindingKey = "kingdee-demo-erp"

// The two declared data classes. Both resolve through the same binding and
// capability; they differ only in whether they declare an observation
// authority, which is what separates an ordinary read from a
// verification-purpose read.
const (
	dataClassWithAuthority    = "erp.finance.purchase_order"
	dataClassWithoutAuthority = "erp.finance.invoice"
)

// Organization placement of both data classes. dream_evidence +
// dream_evidence.read is the only pair in policy.capabilityRequirements that
// addresses the evidence plane; it requires the approve_high_risk permission,
// which is why the demo principal holds that role.
const (
	evidenceResourceType = "dream_evidence"
	evidenceResourceID   = "demo-finance-evidence"
	evidenceCapability   = "dream_evidence.read"
)

// Organization identifiers. Stable so a re-run upserts rather than duplicates.
const (
	orgRootUnit    = "demo-hq"
	orgFinanceUnit = "demo-finance"
	demoUserID     = "demo-finance-controller"
	demoTicketID   = "demo-case-ticket"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("demo-seed: %v", err)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	dsn := strings.TrimSpace(os.Getenv("AGENTNEXUS_POSTGRES_DSN"))
	if dsn == "" {
		return errors.New("AGENTNEXUS_POSTGRES_DSN is required")
	}
	tenant := envOr("AGENTNEXUS_DEMO_TENANT", defaultTenant)
	outputDir := envOr("AGENTNEXUS_DEMO_OUTPUT_DIR", "/run/agentnexus/demo")
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	orgVersion, err := seedOrganization(ctx, pool, tenant)
	if err != nil {
		return err
	}
	log.Printf("demo-seed: organization sealed at version %d", orgVersion)

	pack, err := seedConnectorProduct(ctx, pool, tenant, outputDir)
	if err != nil {
		return err
	}
	log.Printf("demo-seed: connector product %s@%s (%s)", pack.ProductKey, pack.Version, pack.Digest)

	if err := seedCustomerBinding(ctx, pool, tenant, pack); err != nil {
		return err
	}
	log.Printf("demo-seed: customer binding %q pinned to that pack", bindingKey)

	token, err := seedCaseTicket(ctx, pool, tenant, outputDir)
	if err != nil {
		return err
	}
	log.Printf("demo-seed: case ticket %q active for principal %q", demoTicketID, demoUserID)

	if err := writeSourceCatalog(tenant, outputDir); err != nil {
		return err
	}
	if err := writeContentKey(outputDir); err != nil {
		return err
	}
	if err := writeWorkerReceiptSigningKey(outputDir); err != nil {
		return err
	}
	log.Printf("demo-seed: evidence source catalog and content key written under %s", outputDir)
	log.Printf("demo-seed: done. Case ticket credential is in %s (never echoed here, %d bytes)",
		filepath.Join(outputDir, "case-ticket-token"), len(token))
	return nil
}

// seedOrganization writes the enterprise, its two org units, the demo
// principal and the membership that carries the approve_high_risk permission,
// then SEALS a policy version over them.
//
// VERSION ALLOCATION. iam.CreateOrgVersionInput.VersionNumber is caller
// supplied and is NOT allocated inside the publishing transaction, so the
// read below happens outside the lock that protects the write. That is safe
// here only because this command seeds SERIALLY; two concurrent seeders that
// both read the same head would both propose the same number and one would be
// rejected by guard_org_policy_version_seal ("organization policy version must
// strictly increase"). The rejection is loud and atomic, never a partial
// publication — see the walk report for the full analysis.
func seedOrganization(ctx context.Context, pool *pgxpool.Pool, tenant string) (int64, error) {
	service := iam.NewService(iam.NewPostgresStore(pool), iam.WithIDGenerator(func() string {
		// Deterministic: a re-run must not create a second event/version pair.
		return "demo-org-import"
	}))

	if _, err := service.CreateEnterprise(ctx, iam.CreateEnterpriseInput{
		ID: tenant, Name: "AgentNexus Demo Enterprise",
	}); err != nil {
		return 0, fmt.Errorf("create enterprise: %w", err)
	}
	if _, err := service.UpsertEnterpriseUser(ctx, iam.UpsertEnterpriseUserInput{
		ID: demoUserID, EnterpriseID: tenant, DisplayName: "Demo Finance Controller",
	}); err != nil {
		return 0, fmt.Errorf("upsert enterprise user: %w", err)
	}
	if _, err := service.UpsertOrgUnit(ctx, iam.UpsertOrgUnitInput{
		ID: orgRootUnit, EnterpriseID: tenant, Name: "Demo HQ", UnitType: "company",
	}); err != nil {
		return 0, fmt.Errorf("upsert root org unit: %w", err)
	}
	if _, err := service.UpsertOrgUnit(ctx, iam.UpsertOrgUnitInput{
		ID: orgFinanceUnit, EnterpriseID: tenant, ParentID: orgRootUnit, Name: "Demo Finance", UnitType: "department",
	}); err != nil {
		return 0, fmt.Errorf("upsert finance org unit: %w", err)
	}
	// approve_high_risk is what dream_evidence.read requires; a plain "member"
	// would map to the suggest permission and every locate would deny at
	// policy_denied.
	if _, err := service.AddOrgMembership(ctx, iam.AddOrgMembershipInput{
		EnterpriseID: tenant, EnterpriseUserID: demoUserID, OrgUnitID: orgFinanceUnit,
		Role: iam.OrgRole("approve_high_risk"),
	}); err != nil {
		return 0, fmt.Errorf("add org membership: %w", err)
	}

	// Already sealed? Re-publishing would be rejected by the strictly-increasing
	// guard anyway; reporting the existing head keeps the command idempotent.
	var head int64
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(version_number), 0) FROM org_versions WHERE enterprise_id = $1`, tenant).Scan(&head)
	if err != nil {
		return 0, fmt.Errorf("read organization publication head: %w", err)
	}
	if head > 0 {
		return head, nil
	}
	version, err := service.CreateOrgVersion(ctx, iam.CreateOrgVersionInput{
		EnterpriseID:  tenant,
		VersionNumber: head + 1,
		SourceHash:    "demo-seed",
	})
	if err != nil {
		return 0, fmt.Errorf("publish organization version: %w", err)
	}
	return version.VersionNumber, nil
}

// buildProductPack constructs the signed, customer-agnostic Kingdee product
// pack. Everything about it is deterministic except the signature, so a
// re-run computes the same content digest and the binding's foreign key
// keeps pointing at the same row.
func buildProductPack() connector.ProductPack {
	return connector.ProductPack{
		SchemaVersion: connector.ProductPackSchemaVersion,
		ProductKey:    productKey,
		Version:       productVersion,
		Title:         "Kingdee (金蝶) finance ERP — read-only demo product",
		Capabilities: []connector.Capability{{
			Name:   readCapability,
			Title:  "read purchase orders",
			Effect: connector.EffectRead,
			Input: connector.IOSchema{
				Ref:    "schema.erp.purchase_order.read.input",
				Digest: syntheticDigest("erp.purchase_order.read:input"),
			},
			Output: connector.IOSchema{
				Ref:    "schema.erp.purchase_order.read.output",
				Digest: syntheticDigest("erp.purchase_order.read:output"),
			},
		}},
		// A read-only product still has to declare the floor. read means a
		// third-party or uncertified decision context can never reach a write
		// capability of this pack — which is trivially true here, and stated
		// rather than implied because the validator requires it.
		TechnicalSafetyFloor: connector.TechnicalSafetyFloor{EffectCeiling: connector.EffectRead},
		Network:              connector.NetworkRequirements{Egress: []string{"connector.api"}, Isolation: "outbound_only"},
		Runtime:              connector.RuntimeRequirements{Runtime: "http", MinMemoryMB: 64},
		Compatibility: connector.Compatibility{
			RuntimeContract:  connector.VersionRange{Min: "1.0.0"},
			ConnectorRuntime: connector.VersionRange{Min: "0.1.0"},
		},
		Migration: connector.MigrationInfo{FromVersions: []string{}, Notes: "first demo version"},
		Limits:    connector.Limits{MaxConcurrency: 4, MaxRequestsPerMinute: 120},
		SBOM: connector.ArtifactRef{
			Ref: "sbom.connector.kingdee_erp.v1", Digest: syntheticDigest("kingdee:sbom"),
		},
		Provenance: connector.ArtifactRef{
			Ref: "provenance.connector.kingdee_erp.v1", Digest: syntheticDigest("kingdee:provenance"),
		},
	}
}

// seedConnectorProduct signs, imports and stores the pack. Importing through
// the SDK BEFORE the insert is the point: the row can only exist if the
// document already satisfies the closed-world production contract.
func seedConnectorProduct(ctx context.Context, pool *pgxpool.Pool, tenant, outputDir string) (connector.ProductPack, error) {
	signingKey, keyID, err := packSigningKey(outputDir)
	if err != nil {
		return connector.ProductPack{}, err
	}
	pack := buildProductPack()
	pack.Digest = connector.PackContentDigest(pack)
	// A genuine ed25519 signature over the content digest. The SDK checks the
	// signature block's STRUCTURE only — authenticity against a trusted key
	// registry is the certification task's — but signing it properly costs
	// nothing and keeps the seed honest about what the field means.
	pack.Signature = connector.Signature{
		Algorithm: connector.SignatureAlgorithmEd25519,
		KeyID:     keyID,
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(pack.Digest))),
	}

	document, err := json.Marshal(pack)
	if err != nil {
		return connector.ProductPack{}, fmt.Errorf("marshal product pack: %w", err)
	}
	imported, err := connector.ImportProductionPack(document)
	if err != nil {
		return connector.ProductPack{}, fmt.Errorf("the seeded pack is not a valid production pack: %w", err)
	}

	if _, err := pool.Exec(ctx, `
INSERT INTO connector_products (
    tenant_id, product_key, version, digest,
    signature_algorithm, signature_key_id, signature_value,
    sbom_digest, provenance_digest, pack_document)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, product_key, version) DO NOTHING`,
		tenant, imported.ProductKey, imported.Version, imported.Digest,
		imported.Signature.Algorithm, imported.Signature.KeyID, imported.Signature.Value,
		imported.SBOM.Digest, imported.Provenance.Digest, document); err != nil {
		return connector.ProductPack{}, fmt.Errorf("insert connector product: %w", err)
	}

	// A prior run may have stored the same content under a different signing
	// key. The binding's foreign key references the DIGEST, so read back what
	// is actually stored rather than assuming this run's document won.
	var storedDigest string
	if err := pool.QueryRow(ctx,
		`SELECT digest FROM connector_products WHERE tenant_id = $1 AND product_key = $2 AND version = $3`,
		tenant, imported.ProductKey, imported.Version).Scan(&storedDigest); err != nil {
		return connector.ProductPack{}, fmt.Errorf("read back connector product: %w", err)
	}
	imported.Digest = storedDigest
	return imported, nil
}

// seedCustomerBinding stores the customer half: one endpoint, one secret
// REFERENCE (never a value), and the resource mapping that names the customer
// object the semantic capability reads.
func seedCustomerBinding(ctx context.Context, pool *pgxpool.Pool, tenant string, pack connector.ProductPack) error {
	binding := connector.CustomerBinding{
		SchemaVersion: connector.CustomerBindingSchemaVersion,
		BindingKey:    bindingKey,
		Customer:      connector.CustomerRef{Name: "Demo Manufacturing Co.", Ref: "demo-customer"},
		Product: connector.ProductRef{
			ProductKey: pack.ProductKey, Version: pack.Version, Digest: pack.Digest,
		},
		Endpoints: []connector.Endpoint{{
			Name: "kingdee_api", URL: "https://kingdee.demo.invalid/k3cloud/api",
		}},
		// An opaque pointer into a secret store. The value it points at is not
		// part of this seed and is not part of this repository.
		Secrets: []connector.SecretRef{{
			Name: "kingdee_app_secret", Ref: "secretref://demo/kingdee/app",
		}},
		OrgMappings: []connector.OrgMapping{{Unit: orgFinanceUnit, Source: "FIN"}},
		ResourceMappings: []connector.ResourceMapping{{
			Capability: readCapability, Resource: "PUR_PurchaseOrder",
		}},
	}
	document, err := json.Marshal(binding)
	if err != nil {
		return fmt.Errorf("marshal customer binding: %w", err)
	}
	// Same reasoning as the pack: parse through the SDK so an inline secret or
	// an unknown field can never reach the table.
	if _, err := connector.ParseBinding(document); err != nil {
		return fmt.Errorf("the seeded binding is not a valid customer binding: %w", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO connector_bindings (
    tenant_id, binding_key, product_key, product_version, product_digest, binding_document)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, binding_key) DO UPDATE
SET product_key = EXCLUDED.product_key,
    product_version = EXCLUDED.product_version,
    product_digest = EXCLUDED.product_digest,
    binding_document = EXCLUDED.binding_document,
    updated_at = now()`,
		tenant, binding.BindingKey, binding.Product.ProductKey, binding.Product.Version,
		binding.Product.Digest, document); err != nil {
		return fmt.Errorf("insert customer binding: %w", err)
	}
	return nil
}

// seedCaseTicket issues the opaque Access Ticket the walk authenticates with.
// Only its SHA-256 (domain separated, exactly as
// tickets.HashCaseTicketToken computes it) is stored; the credential itself
// goes to a 0600 file and is never logged.
func seedCaseTicket(ctx context.Context, pool *pgxpool.Pool, tenant, outputDir string) (string, error) {
	tokenPath := filepath.Join(outputDir, "case-ticket-token")
	token, err := readOrCreateSecret(tokenPath, func() (string, error) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(raw), nil
	})
	if err != nil {
		return "", fmt.Errorf("provision case ticket credential: %w", err)
	}
	// The verifier requires status=active and a future expiry, so a re-run
	// refreshes the window rather than leaving a stale ticket behind.
	if _, err := pool.Exec(ctx, `
INSERT INTO case_tickets (id, enterprise_id, actor_user_id, request_id, trace_id, status, expires_at, token_hash)
VALUES ($1, $2, $3, $4, $5, 'active', now() + interval '30 days', $6)
ON CONFLICT (id) DO UPDATE
SET status = 'active', expires_at = now() + interval '30 days', token_hash = EXCLUDED.token_hash`,
		demoTicketID, tenant, demoUserID, "demo-seed-request", "demo-seed-trace",
		tickets.HashCaseTicketToken(token)); err != nil {
		return "", fmt.Errorf("insert case ticket: %w", err)
	}
	return token, nil
}

// writeSourceCatalog emits the deployment-authored private semantic registry.
// It is built as the typed struct and validated before it is written, so the
// document on disk can only be one gateway-api will accept.
func writeSourceCatalog(tenant, outputDir string) error {
	catalog := evidence.SourceCatalog{
		SchemaVersion: evidence.SourceCatalogSchemaVersion,
		Sources: []evidence.CatalogSource{
			{
				TenantRef: tenant,
				DataClass: dataClassWithAuthority,
				Connector: evidence.CatalogConnectorRef{
					BindingKey: bindingKey, Capability: readCapability,
				},
				AccessCapability:  evidenceCapability,
				ResourceType:      evidenceResourceType,
				ResourceID:        evidenceResourceID,
				CachedReadAllowed: true,
				// Declared so a verification-purpose read gets PAST the
				// observation-authority gate and stops at whatever is actually
				// missing behind it.
				ObservationAuthority: &evidence.CatalogObservationAuthority{
					Tier: evidence.AuthorityTierSystemOfRecord, FreshnessBoundSeconds: 300,
				},
			},
			{
				TenantRef: tenant,
				DataClass: dataClassWithoutAuthority,
				Connector: evidence.CatalogConnectorRef{
					BindingKey: bindingKey, Capability: readCapability,
				},
				AccessCapability:  evidenceCapability,
				ResourceType:      evidenceResourceType,
				ResourceID:        evidenceResourceID,
				CachedReadAllowed: true,
				// Deliberately NO observation authority: this entry is the
				// control that shows a verification-purpose read failing closed.
			},
		},
	}
	if err := evidence.ValidateSourceCatalog(catalog); err != nil {
		return fmt.Errorf("the seeded source catalog is invalid: %w", err)
	}
	document, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal source catalog: %w", err)
	}
	return os.WriteFile(filepath.Join(outputDir, "evidence-source-catalog.json"), append(document, '\n'), 0o600)
}

// writeContentKey provisions the STABLE AES-256 content key. Stability is the
// whole point: every staged handle records the key reference, so a key that
// changed between restarts would orphan content rather than fail loudly.
func writeContentKey(outputDir string) error {
	_, err := readOrCreateSecret(filepath.Join(outputDir, "evidence-content-key"), func() (string, error) {
		key := make([]byte, evidence.ContentKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(key), nil
	})
	return err
}

// writeWorkerReceiptSigningKey provisions the connector worker's ActionReceipt
// signing key. Like the content key it must be STABLE across restarts: the
// public half is registered in the signing-key registry the ReceiptVerifier
// resolves against, and a receipt outlives the process that signed it. The
// format is base64 (std) of the ed25519 PRIVATE key, matching what
// config.LoadWorkerExecution and cmd/audit-export both read.
func writeWorkerReceiptSigningKey(outputDir string) error {
	_, err := readOrCreateSecret(filepath.Join(outputDir, "worker-receipt-signing-key"), func() (string, error) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(private), nil
	})
	return err
}

// packSigningKey provisions the dev pack signing key, persisted so a re-run
// produces the same signature for the same content.
func packSigningKey(outputDir string) (ed25519.PrivateKey, string, error) {
	encoded, err := readOrCreateSecret(filepath.Join(outputDir, "pack-signing-key"), func() (string, error) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(private), nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("provision pack signing key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, "", errors.New("stored pack signing key is not an ed25519 private key")
	}
	return ed25519.PrivateKey(raw), "agentnexus-demo-pack-key-1", nil
}

// readOrCreateSecret returns the existing 0600 secret at path, or creates one.
// Reuse is what makes every credential this command issues stable across runs.
func readOrCreateSecret(path string, generate func() (string, error)) (string, error) {
	existing, err := os.ReadFile(path)
	if err == nil {
		if value := strings.TrimSpace(string(existing)); value != "" {
			return value, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	value, err := generate()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		return "", err
	}
	return value, nil
}

func syntheticDigest(seed string) string {
	return connector.PackContentDigest(connector.ProductPack{ProductKey: "agentnexus.demo_seed", Title: seed})
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
