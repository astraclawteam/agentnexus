import { describe, expect, it } from "vitest";
import { deriveAppMode } from "./app-mode";

describe("deriveAppMode", () => {
  it("shows API unavailable when setup status cannot be loaded", () => {
    expect(deriveAppMode(null, new Error("offline"))).toBe("api_unavailable");
  });

  it("requires first-run when no enterprise tenant exists", () => {
    expect(
      deriveAppMode({
        state: "unconfigured",
        enterprise_id: "",
        enterprise_name: "",
        admin_user_id: "",
        secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
        services: { gateway_api: "ready" },
        next_required_actions: ["create_enterprise"]
      })
    ).toBe("setup_required");
  });

  it("enters configured console when an enterprise tenant and live setup state exist", () => {
    expect(
      deriveAppMode({
        state: "configured",
        enterprise_id: "ent_dev",
        enterprise_name: "Live Enterprise",
        admin_user_id: "admin_dev",
        secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
        services: { gateway_api: "ready" },
        next_required_actions: []
      })
    ).toBe("configured");
  });
});

