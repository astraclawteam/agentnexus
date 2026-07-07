import { describe, expect, it } from "vitest";
import { deriveFirstRunStep } from "./first-run-machine";
import type { FirstRunChecklistItem, FirstRunStatus } from "./first-run-types";

describe("deriveFirstRunStep", () => {
  it("starts at enterprise tenant when the backend is unconfigured", () => {
    expect(deriveFirstRunStep(status("unconfigured", [{ key: "enterprise_tenant", status: "required", required: true }]))).toBe("tenant");
  });

  it("blocks at environment when a required environment check is blocked", () => {
    expect(
      deriveFirstRunStep(
        status("configured_without_org", [
          { key: "enterprise_tenant", status: "completed", required: true },
          { key: "environment_check", status: "blocked", required: true }
        ])
      )
    ).toBe("environment");
  });

  it("moves to organization import after tenant, environment, and secret refs are ready", () => {
    expect(
      deriveFirstRunStep(
        status("configured_without_org", [
          { key: "enterprise_tenant", status: "completed", required: true },
          { key: "environment_check", status: "completed", required: true },
          { key: "secret_refs", status: "completed", required: true },
          { key: "organization_import", status: "required", required: true }
        ])
      )
    ).toBe("org");
  });

  it("recommends connector verification before agent dry-run after org import", () => {
    expect(
      deriveFirstRunStep(
        status("configured", [
          { key: "enterprise_tenant", status: "completed", required: true },
          { key: "organization_import", status: "completed", required: true },
          { key: "connector_verification", status: "recommended", required: false },
          { key: "gateway_agent_dry_run", status: "recommended", required: false }
        ])
      )
    ).toBe("connectors");
  });
});

function status(state: string, checklist: Partial<FirstRunChecklistItem>[]): FirstRunStatus {
  return {
    state,
    enterprise_id: state === "unconfigured" ? "" : "ent_dev",
    enterprise_name: state === "unconfigured" ? "" : "Local Enterprise",
    admin_user_id: "admin_dev",
    checklist: checklist.map((item) => ({
      key: item.key || "unknown",
      status: item.status || "required",
      required: item.required ?? true,
      title: item.title || "Step",
      action: item.action || "continue"
    }))
  };
}

