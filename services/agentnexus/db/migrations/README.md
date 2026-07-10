# Database migration notes

## Versioned organization policy snapshots

`000004_versioned_org_policy_snapshots.sql` is a pre-release migration for the Task 3 authorization model. It is not a rolling-upgrade bridge for older gateway binaries: deploy the migration and the snapshot-aware IAM/gateway binaries as one release while writes are stopped.

The migration takes `SHARE ROW EXCLUSIVE` locks on organization versions, units, and memberships. For each enterprise it backfills only the latest existing version from the current live organization state. Earlier historical versions are deliberately not fabricated. Any invalid parent, membership, role, or cross-enterprise reference aborts the migration transaction.

After migration, every new `org_versions` row is published transactionally with immutable unit and membership snapshot rows. Authorization reads the latest version and that exact snapshot inside one read-only repeatable-read transaction; it never authorizes from the mutable live organization tables.

Policy evaluation accepts at most 10,000 organization units, 100,000 actor memberships, and organization depth 256. SQL reads use limit-plus-one bounds so an oversized snapshot fails closed before unbounded conversion or graph work.
