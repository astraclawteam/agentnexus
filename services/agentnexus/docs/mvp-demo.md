# AgentNexus MVP Demo

This demo runs the open-core MVP flow without external services. It proves the Agent-first gateway path with in-memory IAM, OpenFGA-style relationship checks, policy evaluation, ticketing, connector runtime execution, and audit hash-chain verification.

## Scenario

1. Seed `ent_demo`.
2. Load the WeCom organization fixture from `tests/fixtures/org_import/wecom_org_sample.json`.
3. Build a Gateway Agent organization import preview and auto-import clean rows.
4. Create `org_version` `1` with the source fixture hash.
5. Create a department-to-knowledge-space relation in the in-memory OpenFGA checker.
6. Simulate a Claw resource request from `user_ada`.
7. Create a `case_ticket`.
8. Evaluate OpenFGA visibility plus the Policy DSL fixture.
9. Create a `step_grant`.
10. Execute a file-storage connector read using `tests/fixtures/connectors/file_storage_manifest.yaml`.
11. Append audit events for org import, case ticket, policy decision, step grant, and connector read.
12. Verify the audit hash chain.

## Run

```powershell
cd E:\xiaozhiclaw\agentnexus\services\agentnexus
go test ./tests/e2e -run TestMVPOrgImportAndAccess
```

## Fixtures

- `tests/fixtures/org_import/wecom_org_sample.json` contains departments, employees, and memberships.
- `tests/fixtures/policies/basic_policy.yaml` allows legal knowledge-space reads with `allow_with_masking`.
- `tests/fixtures/connectors/file_storage_manifest.yaml` declares a read-only file-storage resource.

The demo intentionally uses open-core primitives only. Enterprise production deployment, customer overlays, managed secret providers, and commercial connectors remain in `agentnexus-enterprise`.
