-- 000015_evidence_source_binding_authority.sql
--
-- Observation-authority columns for the private semantic registry (GA Task 0D
-- amendment, deferred at 000008 and taken up by task B3).
--
-- Why this was deferred and why the deferral has now expired. 000008 shipped
-- evidence_source_bindings without an authority declaration, and
-- evidence.PostgresStore.UpsertSourceBinding refused any binding carrying one
-- rather than persist the row and silently DROP the declaration. Its stated
-- reason was that migration slots 000009-000011 were reserved for Tasks
-- 0E/0F/0G, so extending the table had to wait for the task that next opened a
-- slot. Those three slots are now filled (approval_transmission,
-- durable_actions, signed_audit_chain), as are 000012-000014, so the
-- reservation no longer holds anything back and the refusal can be lifted.
--
-- The consequence of the gap was total, not partial: sourceBindingFromRow could
-- never populate AuthorityTier/FreshnessBound, so over PostgreSQL EVERY
-- verification-purpose read denied at observation_authority_undeclared
-- (service.go), regardless of whether an ObservationSigner was wired. The
-- evidence plane's verification half was unreachable by construction.
--
-- The declaration is ALL-OR-NOTHING and this schema enforces it independently
-- of the service: a frozen tier together with a strictly positive freshness
-- bound, or neither. A tier without a bound is an unbounded observation, and a
-- bound without a tier is freshness under no declared authority; both are
-- undeclarable, so neither can be stored. Service.RegisterSourceBinding applies
-- the same rule, and this CHECK is the durable backstop for any other writer.
--
-- The tier vocabulary is the frozen literal set of evidence/observation.go
-- (system_of_record, authoritative_replica, derived), mirrored here BY VALUE
-- for the same reason that file mirrors the connector SDK ladder by value:
-- both vocabularies are contract-frozen, so drift is a contract change and
-- never a refactor. The empty string is the explicit "not declared" state
-- rather than NULL, matching source_capability's existing convention on this
-- table and keeping sourceBindingFromRow free of a nullable string.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE evidence_source_bindings
    ADD COLUMN authority_tier TEXT NOT NULL DEFAULT '',
    ADD COLUMN freshness_bound_seconds BIGINT NOT NULL DEFAULT 0;

ALTER TABLE evidence_source_bindings
    ADD CONSTRAINT chk_evidence_source_bindings_authority_tier
        CHECK (authority_tier IN ('', 'system_of_record', 'authoritative_replica', 'derived')),
    ADD CONSTRAINT chk_evidence_source_bindings_freshness_bound
        CHECK (freshness_bound_seconds >= 0),
    -- All-or-nothing: declared together (tier set AND bound strictly positive)
    -- or not at all. This is the durable half of the rule
    -- Service.RegisterSourceBinding enforces in Go.
    ADD CONSTRAINT chk_evidence_source_bindings_authority_declared
        CHECK ((authority_tier = '' AND freshness_bound_seconds = 0)
            OR (authority_tier <> '' AND freshness_bound_seconds > 0));

COMMENT ON COLUMN evidence_source_bindings.authority_tier IS
    'Frozen observation-authority tier under which this source reports (evidence/observation.go AuthorityTier* literals); empty means not declared, which fails verification-purpose reads closed.';
COMMENT ON COLUMN evidence_source_bindings.freshness_bound_seconds IS
    'Bound within which an observation staged from this source may be treated as fresh; 0 exactly when authority_tier is empty.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE evidence_source_bindings
    DROP CONSTRAINT IF EXISTS chk_evidence_source_bindings_authority_declared,
    DROP CONSTRAINT IF EXISTS chk_evidence_source_bindings_freshness_bound,
    DROP CONSTRAINT IF EXISTS chk_evidence_source_bindings_authority_tier;

ALTER TABLE evidence_source_bindings
    DROP COLUMN IF EXISTS freshness_bound_seconds,
    DROP COLUMN IF EXISTS authority_tier;
-- +goose StatementEnd
