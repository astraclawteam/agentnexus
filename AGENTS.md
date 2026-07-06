# AgentNexus AI Coding Rules

This file is the mandatory entry point for AI coding agents working in this repository.
Read it before editing files, running generators, or proposing implementation changes.

## Repository Role

`agentnexus` is the open-core repository for AgentNexus.
It must remain buildable, testable, and runnable without `agentnexus-enterprise`.

Open-core contains:

- Core Gateway Runtime API and Gateway Agent Control Plane.
- Public SDKs, API contracts, connector manifest schema, basic connector runtime.
- Policy, Access Ticket, Step Grant, Secret Provider, and Audit foundations.
- Local/dev SaaS and private deployment profiles.
- The open-core admin console and reusable Claw-runtime-style UI primitives.

Open-core must not contain:

- Customer-specific connector code, templates, credentials, or field mappings.
- Commercial connector implementation details.
- Enterprise license enforcement.
- Production private-deployment automation.
- Private roadmap, customer names, private endpoints, or secrets.

## Hard Boundaries

- Do not import code from `agentnexus-enterprise`.
- Do not require `agentnexus-enterprise` to build, test, or run this repo.
- Do not place public SDKs inside `internal`.
- Do not expose secret values in logs, test output, fixtures, or documentation.
- Do not bypass Access Ticket, Step Grant, Policy, Secret Provider, or Audit paths for convenience.
- Do not add customer-specific behavior to open-core fixtures or tests.
- Do not introduce a technology choice that blocks SaaS, private, or hybrid deployment modes.

## Public Contract Locations

Enterprise extensions may depend only on published open-core contracts:

- Go module: `github.com/astraclawteam/agentnexus/services/agentnexus`
- Public Go SDKs: `sdk/go/*`
- OpenAPI: `services/agentnexus/api/openapi`
- Proto: `services/agentnexus/api/proto/agentnexus/*/v1`
- OCI images: `agentnexus/<service>:<semver-or-sha>`
- Helm chart: `agentnexus`

Anything under `services/agentnexus/internal/*` is private implementation detail.

## Required Working Method

Before editing:

1. Read the active plan in `docs/plans` or `docs/superpowers/plans` when one exists.
2. Identify the current Goal or task.
3. Check existing patterns before adding new packages, dependencies, or abstractions.
4. Keep changes scoped to the current Goal.

During implementation:

- Prefer small, testable changes.
- Write or update tests for behavior changes.
- Keep public API and SDK changes backward compatible unless an explicit migration plan exists.
- Use structured parsers and typed APIs instead of ad hoc string manipulation.
- Add comments only when they explain non-obvious business or security constraints.
- Keep generated files reproducible and document the generation command.

Before finishing:

- Run the verification command for the current Goal.
- Report any command that could not be run.
- Check that no enterprise-only material was added to open-core.
- Check that no secrets or private customer details were added.

## AI Safety Rules

AI agents must not:

- Invent new architecture when the plan already specifies one.
- Move enterprise-only features into open-core to make a demo easier.
- Replace ADK Go v2, llmrouter, NATS JetStream, OpenFGA, PostgreSQL, or the Secret Provider model without explicit human approval.
- Change repository boundaries without human approval.
- Use destructive git commands such as `git reset --hard` or `git checkout --` unless explicitly requested.
- Hide failing tests or remove tests to make a task pass.
- Commit unrelated formatting churn.

If a requirement conflicts with this file, stop and ask for human direction.
