# AI Coding Rules

These rules apply to Copilot, Codex, Claude Code, Cursor, and any other AI-assisted coding workflow.

## Required Context

An AI agent must read:

1. `AGENTS.md`
2. The current Goal plan, if present.
3. The files it will modify.
4. Related tests or contracts.

## Scope Control

AI agents must:

- Work on one Goal or task at a time.
- Keep edits close to the requested scope.
- Preserve existing architecture unless explicitly asked to change it.
- Ask before changing public API, SDK, schema, deployment topology, or repo boundaries.
- Prefer small changes over broad rewrites.

AI agents must not:

- Add enterprise-only code to open-core.
- Add customer data, secrets, private endpoints, or private roadmap details.
- Skip governance paths to make a demo pass.
- Delete tests because they fail.
- Change unrelated files for formatting or style.
- Introduce hidden background services or undocumented generators.

## Prompt Template For AI Coding

Use this shape when assigning work:

```text
Repository: agentnexus
Current Goal: <Goal number and title>
Allowed scope: <files or packages>
Required rules:
- Read AGENTS.md first.
- Keep open-core independent from agentnexus-enterprise.
- Do not bypass Access Ticket, Policy, Secret Provider, or Audit.
- Do not add customer-specific or enterprise-only code.
- Update tests and run verification before reporting done.
Verification:
- <exact command>
```

## Completion Report

AI agents must report:

- What changed.
- Which verification commands passed.
- Which verification commands were skipped and why.
- Any public contract or migration impact.
- Any risk that needs human review.
