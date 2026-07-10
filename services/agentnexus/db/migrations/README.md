# Database migration notes

## Sealed organization policy snapshots

`000004_versioned_org_policy_snapshots.sql` adds the publication boundary used by AgentAtlas authorization. The migration never copies current live organization data into an existing version. Every pre-existing `org_versions` row remains unsealed and therefore unusable for authorization.

After applying the migration, an organization publisher must create a new, monotonically increasing version through the IAM publication workflow. Existing rows have `policy_snapshot_publishable=false`; only the insert trigger can mark a new version publishable, and a legacy row can never be sealed. The trigger rejects zero, negative, duplicate, and backward version numbers and serializes publishers per enterprise with a transaction-scoped advisory lock. One repeatable-read transaction creates the organization event and an unsealed version, copies units and memberships, seals that version, and commits. Until the first such transaction commits, browser profile resolution and permission decisions fail closed; operators must not manually seal an older version. An empty database likewise becomes authorizable only after its first controlled publication.

Database triggers lock the owning version row before every snapshot INSERT/UPDATE/DELETE. That row lock conflicts with the seal UPDATE: a mutation that locks first completes before sealing, while a seal that locks first causes a waiting mutation to observe the sealed state and fail. TRUNCATE is rejected at all times. Sealing cannot be reversed, version identity and publishability cannot be changed, and organization versions cannot be deleted.

Publisher-only writes are a deployment prerequisite, not a privilege policy installed by this migration. Deployment SQL must provision a publisher role that can insert organization events/versions and write snapshot rows, and a gateway/runtime role limited to reading sealed versions and snapshots. The runtime role must not receive INSERT/UPDATE/DELETE/TRUNCATE on snapshot tables or UPDATE/DELETE on `org_versions`; operators should use `GRANT`/`REVOKE` appropriate to their role names. The migration itself provides row-level state invariants but intentionally does not create environment-specific roles.

Before production rollout, run a live PostgreSQL two-connection acceptance test for both lock orders (mutation-first and seal-first), plus concurrent publishers proposing the same next version. The repository's deterministic SQL contracts and transaction fakes do not substitute for that deployment-level lock test.

Policy evaluation accepts at most 10,000 organization units, 100,000 actor memberships, and organization depth 256. SQL reads use limit-plus-one bounds so an oversized snapshot fails closed before unbounded conversion or graph work.

Historical snapshot rows retain foreign keys to their organization version and enterprise users with `RESTRICT` semantics. User/version deletion therefore requires an explicit governance or anonymization workflow; do not destroy or mutate historical authorization evidence to satisfy routine lifecycle operations.
