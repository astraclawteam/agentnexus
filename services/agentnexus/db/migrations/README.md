# Database migration notes

## Sealed organization policy snapshots

`000004_versioned_org_policy_snapshots.sql` adds the publication boundary used by AgentAtlas authorization. The migration never copies current live organization data into an existing version. Every pre-existing `org_versions` row remains unsealed and therefore unusable for authorization.

After applying the migration, an organization publisher must create a new, monotonically increasing version through the IAM publication workflow. Existing rows have `policy_snapshot_publishable=false`; only the insert trigger can mark a new version publishable, and a legacy row can never be sealed. The trigger rejects zero, negative, duplicate, and backward version numbers and retains a transaction-scoped advisory lock as a direct-SQL defense.

The normal PostgreSQL publisher uses a stronger ordering boundary: it acquires a dedicated pooled connection, takes the matching enterprise session advisory lock before beginning any transaction, and only then starts the repeatable-read/read-write transaction on that same physical connection. Therefore a publisher proposing version 43 cannot establish an old snapshot, wait while version 44 commits, and then publish 43: after 44 unlocks, the 43 transaction begins with a fresh snapshot and the strict-maximum trigger rejects it. The same ordering permits only one concurrent publisher proposing the same next version. The event, unsealed version, unit and membership copies, seal, and commit remain in that single transaction.

Session unlock uses a cancellation-detached bounded cleanup context. A connection is returned to the pool only after the matching unlock succeeds; on unlock failure it is removed from the pool and closed. Until the first controlled publication commits, browser profile resolution and permission decisions fail closed; operators must not manually seal an older version. An empty database likewise becomes authorizable only after its first controlled publication.

Database triggers lock the owning version row before every snapshot INSERT/UPDATE/DELETE. That row lock conflicts with the seal UPDATE: a mutation that locks first completes before sealing, while a seal that locks first causes a waiting mutation to observe the sealed state and fail. TRUNCATE is rejected at all times. Sealing cannot be reversed, version identity and publishability cannot be changed, and organization versions cannot be deleted.

Publisher-only writes are a deployment prerequisite, not a privilege policy installed by this migration. Deployment SQL must provision a publisher role that can insert organization events/versions and write snapshot rows, and a gateway/runtime role limited to reading sealed versions and snapshots. The runtime role must not receive INSERT/UPDATE/DELETE/TRUNCATE on snapshot tables or UPDATE/DELETE on `org_versions`; operators should use `GRANT`/`REVOKE` appropriate to their role names. The migration itself provides row-level state invariants but intentionally does not create environment-specific roles.

Before production rollout, run a live PostgreSQL two-connection acceptance test for both snapshot/seal lock orders (mutation-first and seal-first), concurrent publishers proposing the same next version, and the different-version race where 44 obtains the lock before a waiting 43. The repository's deterministic SQL contracts and transaction fakes do not substitute for that deployment-level lock test.

Policy evaluation accepts at most 10,000 organization units, 100,000 actor memberships, and organization depth 256. SQL reads use limit-plus-one bounds so an oversized snapshot fails closed before unbounded conversion or graph work.

Historical snapshot rows retain foreign keys to their organization version and enterprise users with `RESTRICT` semantics. User/version deletion therefore requires an explicit governance or anonymization workflow; do not destroy or mutate historical authorization evidence to satisfy routine lifecycle operations.
