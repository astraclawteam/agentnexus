# First-Run Tenant Onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the first-run page into a SaaS-style enterprise tenant onboarding flow that tells users what to do, in what order, and what will happen next.

**Architecture:** Keep existing first-run APIs and update only the React console experience. `FirstRunSetup` becomes a guided four-step tenant initialization wizard: enterprise tenant, secret refs, org source preview, confirmation into live console.

**Tech Stack:** React, Vitest Testing Library, existing gateway-api setup/org-import endpoints, CSS in the enterprise console package.

---

### Task 1: Test Guided Tenant Onboarding

**Files:**
- Modify: `packages/enterprise-gateway-console/src/FirstRunSetup.test.tsx`

- [ ] Add assertions that the page explains SaaS enterprise tenant setup.
- [ ] Add assertions for the four visible steps: enterprise tenant, secret refs, organization import, live console.
- [ ] Add assertions that only the current step's primary action is visible.
- [ ] Run `npm test --workspace packages/enterprise-gateway-console -- --run FirstRunSetup` and confirm the new test fails before implementation.

### Task 2: Implement Four-Step First-Run Wizard

**Files:**
- Modify: `packages/enterprise-gateway-console/src/FirstRunSetup.tsx`
- Modify: `packages/enterprise-gateway-console/src/styles.css`

- [ ] Replace the flat grid with a stepper and current-step panel.
- [ ] Rename enterprise context to enterprise tenant in user-facing copy.
- [ ] Add a right-side guidance panel explaining current step, data handling, and next result.
- [ ] Gate actions in sequence: save enterprise, validate refs, preview org, confirm import.
- [ ] Keep fields editable and preserve existing API calls.

### Task 3: Verify Browser Flow

**Files:**
- Modify: no production files unless verification finds a bug.

- [ ] Run `npm test --workspace packages/enterprise-gateway-console`.
- [ ] Run `npm run build --workspace packages/enterprise-gateway-console`.
- [ ] Use the in-app browser at `http://127.0.0.1:5173/` to verify the user can see the stepper and clear primary action.
- [ ] Verify Chinese copy uses enterprise tenant language and no longer presents four unstructured form blocks.
