# Database migration notes

## Sealed organization policy snapshots

`000004_versioned_org_policy_snapshots.sql` adds the publication boundary used by AgentAtlas authorization. The migration never copies current live organization data into an existing version. Every pre-existing `org_versions` row remains unsealed and therefore unusable for authorization.

After applying the migration, an organization publisher must create a new, monotonically increasing version through the IAM publication workflow. One repeatable-read transaction creates the organization event and an unsealed version, copies units and memberships, seals that version, and commits. Until the first such transaction commits, browser profile resolution and permission decisions fail closed; operators must not manually seal an older version. An empty database likewise becomes authorizable only after its first controlled publication.

Snapshot tables are publisher-write-only. Gateway authorization reads only the latest sealed version and its exact snapshot in a read-only repeatable-read transaction; it never falls back to live organization tables or an unsealed/older maximum version. Database triggers allow snapshot row changes only while the owning version is unsealed, reject INSERT/UPDATE/DELETE after sealing, and reject TRUNCATE at all times. Sealing cannot be reversed and sealed version identity fields cannot be changed or deleted.

Policy evaluation accepts at most 10,000 organization units, 100,000 actor memberships, and organization depth 256. SQL reads use limit-plus-one bounds so an oversized snapshot fails closed before unbounded conversion or graph work.

Historical snapshot rows retain foreign keys to their organization version and enterprise users with `RESTRICT` semantics. User/version deletion therefore requires an explicit governance or anonymization workflow; do not destroy or mutate historical authorization evidence to satisfy routine lifecycle operations.
