-- name: CreateConnectorPackage :one
INSERT INTO connector_packages (id, name, manifest_version)
VALUES ($1, $2, $3)
RETURNING id, name, manifest_version, created_at;

-- name: GetConnectorPackage :one
SELECT id, name, manifest_version, created_at
FROM connector_packages
WHERE id = $1;

-- name: CreateConnectorInstance :one
INSERT INTO connector_instances (id, enterprise_id, connector_package_id, name, status)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, enterprise_id, connector_package_id, name, status, created_at;

-- name: ListConnectorInstances :many
SELECT id, enterprise_id, connector_package_id, name, status, created_at
FROM connector_instances
WHERE enterprise_id = $1
ORDER BY created_at DESC;

-- name: CreateConnectorHealthEvent :one
INSERT INTO connector_health_events (id, enterprise_id, connector_instance_id, status, message)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, enterprise_id, connector_instance_id, status, message, created_at;

-- Signed Connector Product Packs and Customer Bindings (migration 000012), read
-- by the private worker BindingResolver. Every statement below is scoped by
-- tenant_id in its own WHERE clause: the tenant of a dispatch is server-authored
-- and a cross-tenant binding must be unreachable, not merely unselected.

-- name: InsertConnectorProduct :one
-- Products are immutable per (tenant, key, version): an upgrade INSERTs a new
-- version and re-points a binding, it never rewrites one. Re-importing the same
-- version is therefore a conflict, not an update.
INSERT INTO connector_products (
    tenant_id, product_key, version, digest, signature_algorithm, signature_key_id,
    signature_value, sbom_digest, provenance_digest, pack_document
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING tenant_id, product_key, version, digest, signature_algorithm, signature_key_id,
    signature_value, sbom_digest, provenance_digest, pack_document, created_at;

-- name: UpsertConnectorBinding :one
-- A binding is re-pointed (not rewritten) by a product upgrade, so the product
-- reference is the only mutable half besides the document itself.
INSERT INTO connector_bindings (
    tenant_id, binding_key, product_key, product_version, product_digest, binding_document
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, binding_key) DO UPDATE
    SET product_key = EXCLUDED.product_key,
        product_version = EXCLUDED.product_version,
        product_digest = EXCLUDED.product_digest,
        binding_document = EXCLUDED.binding_document,
        updated_at = now()
RETURNING tenant_id, binding_key, product_key, product_version, product_digest,
    binding_document, created_at, updated_at;

-- name: ListConnectorBindingsForCapability :many
-- Every binding of this tenant whose PINNED pack declares the capability.
--
-- The join is on the full (product_key, version, digest) tuple, which is the
-- foreign key: a binding can only ever reach the exact signed pack content it
-- pinned, so a product upgrade that inserts a new version cannot silently move
-- an existing binding onto different code.
--
-- This returns EVERY match rather than LIMIT 1 on purpose. Two bindings
-- declaring the same capability is an ambiguous resolution, and the resolver
-- must fail closed on it; a LIMIT here would instead pick an arbitrary customer
-- binding by sort order and execute a real side effect against it.
SELECT b.tenant_id, b.binding_key, b.product_key, b.product_version, b.product_digest,
    b.binding_document, p.pack_document, p.signature_key_id, p.signature_value
FROM connector_bindings b
JOIN connector_products p
    ON p.tenant_id = b.tenant_id
   AND p.product_key = b.product_key
   AND p.version = b.product_version
   AND p.digest = b.product_digest
WHERE b.tenant_id = $1
  AND p.pack_document->'capabilities' @> jsonb_build_array(jsonb_build_object('name', sqlc.arg(capability)::text))
ORDER BY b.binding_key;
