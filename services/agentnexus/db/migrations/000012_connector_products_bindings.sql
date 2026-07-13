-- +goose Up
-- +goose StatementBegin
-- GA Task 2: signed Connector Product Packs and Customer Bindings.
-- Schema only; queries and generated code arrive in a later task. The two tables
-- model the frozen separation between a reusable, resellable, customer-agnostic
-- product (connector_products) and its customer-specific binding
-- (connector_bindings). A product upgrade inserts a new product version and
-- re-points a binding's reference; it never rewrites a binding.

-- Every row carries a mandatory tenant identity per the GA tenancy commitment.
CREATE TABLE connector_products (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> '' AND btrim(tenant_id) = tenant_id),
    product_key TEXT NOT NULL CHECK (product_key ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
    version TEXT NOT NULL CHECK (version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
    digest TEXT NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    signature_algorithm TEXT NOT NULL CHECK (signature_algorithm = 'ed25519'),
    signature_key_id TEXT NOT NULL CHECK (signature_key_id <> ''),
    signature_value TEXT NOT NULL CHECK (signature_value <> ''),
    sbom_digest TEXT NOT NULL CHECK (sbom_digest ~ '^sha256:[0-9a-f]{64}$'),
    provenance_digest TEXT NOT NULL CHECK (provenance_digest ~ '^sha256:[0-9a-f]{64}$'),
    pack_document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, product_key, version),
    UNIQUE (tenant_id, digest),
    -- A binding references a pack by this exact (product, version, digest) tuple.
    UNIQUE (tenant_id, product_key, version, digest),
    -- Only the frozen production product form is admitted: schema_version v1 and
    -- never a development migration pack (development=true).
    CONSTRAINT chk_connector_products_schema
        CHECK (pack_document->>'schema_version' = 'connector.product/v1'),
    CONSTRAINT chk_connector_products_not_development
        CHECK (COALESCE((pack_document->>'development')::boolean, false) = false),
    -- The stored digest and signature identity match the document, so an
    -- unsigned or digestless pack can never be persisted as a production pack.
    CONSTRAINT chk_connector_products_digest_matches
        CHECK (pack_document->>'digest' = digest),
    CONSTRAINT chk_connector_products_signature_matches
        CHECK (pack_document#>>'{signature,key_id}' = signature_key_id
           AND pack_document#>>'{signature,value}' = signature_value),
    -- Defense-in-depth backstop against customer topology in a resellable pack.
    -- This is NOT the authoritative gate: the closed-world guarantee is the
    -- connector SDK's ImportProductionPack / ParseProductPack (a closed Go struct
    -- plus a closed JSON Schema 2020-12 with additionalProperties:false), which
    -- rejects ANY field the pack schema does not declare. This CHECK is only a
    -- partial denylist of the best-known customer-topology keys at any depth and
    -- mirrors the SDK's forbidden-key set; a denylist can never equal the
    -- closed-world schema, so persistence code (bulk import, admin tools,
    -- backfills) must import through the SDK rather than trust this constraint.
    CONSTRAINT chk_connector_products_customer_agnostic CHECK (
        NOT (pack_document @? '$.**.customer')
        AND NOT (pack_document @? '$.**.customer_name')
        AND NOT (pack_document @? '$.**.customer_id')
        AND NOT (pack_document @? '$.**.tenant_name')
        AND NOT (pack_document @? '$.**.endpoint')
        AND NOT (pack_document @? '$.**.endpoints')
        AND NOT (pack_document @? '$.**.base_url')
        AND NOT (pack_document @? '$.**.url')
        AND NOT (pack_document @? '$.**.uri')
        AND NOT (pack_document @? '$.**.host')
        AND NOT (pack_document @? '$.**.hostname')
        AND NOT (pack_document @? '$.**.port')
        AND NOT (pack_document @? '$.**.credential')
        AND NOT (pack_document @? '$.**.credentials')
        AND NOT (pack_document @? '$.**.password')
        AND NOT (pack_document @? '$.**.token')
        AND NOT (pack_document @? '$.**.api_key')
        AND NOT (pack_document @? '$.**.apikey')
        AND NOT (pack_document @? '$.**.access_key')
        AND NOT (pack_document @? '$.**.secret_key')
        AND NOT (pack_document @? '$.**.client_secret')
        AND NOT (pack_document @? '$.**.secret')
        AND NOT (pack_document @? '$.**.secrets')
        AND NOT (pack_document @? '$.**.secret_ref')
        AND NOT (pack_document @? '$.**.dsn')
        AND NOT (pack_document @? '$.**.connection_string')
        AND NOT (pack_document @? '$.**.conn_string')
        AND NOT (pack_document @? '$.**.jdbc_url')
        AND NOT (pack_document @? '$.**.table')
        AND NOT (pack_document @? '$.**.table_name')
        AND NOT (pack_document @? '$.**.schema_name')
        AND NOT (pack_document @? '$.**.collection')
        AND NOT (pack_document @? '$.**.api_path')
        AND NOT (pack_document @? '$.**.path')
        AND NOT (pack_document @? '$.**.route')
        AND NOT (pack_document @? '$.**.resource_path')
        AND NOT (pack_document @? '$.**.field_mapping')
        AND NOT (pack_document @? '$.**.field_mappings')
        AND NOT (pack_document @? '$.**.mapping')
        AND NOT (pack_document @? '$.**.mappings')
        AND NOT (pack_document @? '$.**.org_mapping')
        AND NOT (pack_document @? '$.**.org_mappings')
        AND NOT (pack_document @? '$.**.resource_mapping')
        AND NOT (pack_document @? '$.**.resource_mappings')
        AND NOT (pack_document @? '$.**.binding')
        AND NOT (pack_document @? '$.**.bindings')
        AND NOT (pack_document @? '$.**.extensions')
    )
);

COMMENT ON TABLE connector_products IS
    'Signed, resellable, customer-agnostic Connector Product Packs (GA Task 2). One row per (tenant, product_key, version); a product upgrade inserts a new version and never rewrites a binding.';
COMMENT ON COLUMN connector_products.digest IS
    'sha256 over the canonical pack content excluding signature and digest; the signature signs this digest.';

-- The customer-specific half: endpoints, secret references (never inline
-- secrets) and mappings, pinned to one exact product pack by content digest.
CREATE TABLE connector_bindings (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> '' AND btrim(tenant_id) = tenant_id),
    binding_key TEXT NOT NULL CHECK (binding_key <> ''),
    product_key TEXT NOT NULL,
    product_version TEXT NOT NULL,
    product_digest TEXT NOT NULL CHECK (product_digest ~ '^sha256:[0-9a-f]{64}$'),
    binding_document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, binding_key),
    CONSTRAINT chk_connector_bindings_schema
        CHECK (binding_document->>'schema_version' = 'connector.binding/v1'),
    -- A binding references exactly one existing signed product pack. Because the
    -- reference is a foreign key on (product_key, version, digest), a product
    -- upgrade that inserts a new version leaves every existing binding untouched.
    CONSTRAINT fk_connector_bindings_product
        FOREIGN KEY (tenant_id, product_key, product_version, product_digest)
        REFERENCES connector_products (tenant_id, product_key, version, digest),
    -- Defense-in-depth backstop against inline secret material. This is NOT the
    -- authoritative gate: the closed-world guarantee is the connector SDK's
    -- ParseBinding / ValidateBinding (a closed Go struct, a closed JSON Schema,
    -- and an explicit inline-secret key scan over the free-form extensions).
    -- This CHECK is only a partial denylist of the best-known inline-secret keys
    -- at any depth and mirrors the SDK's forbidden-secret set; a denylist can
    -- never equal the closed-world schema, so persistence code must import
    -- through the SDK rather than trust this constraint.
    CONSTRAINT chk_connector_bindings_no_inline_secret CHECK (
        NOT (binding_document @? '$.**.value')
        AND NOT (binding_document @? '$.**.secret')
        AND NOT (binding_document @? '$.**.secret_value')
        AND NOT (binding_document @? '$.**.password')
        AND NOT (binding_document @? '$.**.passwd')
        AND NOT (binding_document @? '$.**.token')
        AND NOT (binding_document @? '$.**.access_token')
        AND NOT (binding_document @? '$.**.refresh_token')
        AND NOT (binding_document @? '$.**.api_key')
        AND NOT (binding_document @? '$.**.apikey')
        AND NOT (binding_document @? '$.**.private_key')
        AND NOT (binding_document @? '$.**.privatekey')
        AND NOT (binding_document @? '$.**.credential')
        AND NOT (binding_document @? '$.**.credentials')
        AND NOT (binding_document @? '$.**.access_key')
        AND NOT (binding_document @? '$.**.secret_key')
        AND NOT (binding_document @? '$.**.client_secret')
        AND NOT (binding_document @? '$.**.bearer')
        AND NOT (binding_document @? '$.**.passphrase')
    )
);

COMMENT ON TABLE connector_bindings IS
    'Customer-specific bindings (GA Task 2): endpoints, secret references and mappings pinned to one exact signed product pack. Never rewritten by a product upgrade.';

CREATE INDEX idx_connector_bindings_tenant_product
    ON connector_bindings (tenant_id, product_key, product_version);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS connector_bindings;
DROP TABLE IF EXISTS connector_products;
-- +goose StatementEnd
