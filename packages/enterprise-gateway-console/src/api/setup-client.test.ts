import { afterEach, describe, expect, it, vi } from "vitest";
import { loadSetupEnvironment, loadSetupStatus } from "./setup-client";

describe("setup-client", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("loads setup status with session, environment, and checklist", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          state: "unconfigured",
          enterprise_id: "",
          enterprise_name: "",
          admin_user_id: "",
          session: { mode: "dev_admin", actor_user_id: "admin_dev", secure: false },
          secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
          environment: { overall_status: "warning", checks: [] },
          checklist: [{ key: "enterprise_tenant", status: "required", required: true, title: "Create tenant", action: "save" }],
          services: { gateway_api: "ready" },
          next_required_actions: ["create_enterprise"]
        }),
        { headers: { "Content-Type": "application/json" } }
      )
    );

    const status = await loadSetupStatus();

    expect(status.session?.mode).toBe("dev_admin");
    expect(status.environment?.overall_status).toBe("warning");
    expect(status.checklist?.[0].key).toBe("enterprise_tenant");
  });

  it("loads environment diagnostics", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ overall_status: "ready", checks: [{ key: "gateway_api", status: "ready", message: "ok" }] }), {
        headers: { "Content-Type": "application/json" }
      })
    );

    const environment = await loadSetupEnvironment();

    expect(environment.overall_status).toBe("ready");
    expect(environment.checks[0].key).toBe("gateway_api");
  });
});

