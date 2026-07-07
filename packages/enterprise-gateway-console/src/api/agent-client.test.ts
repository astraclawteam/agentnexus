import { afterEach, describe, expect, it, vi } from "vitest";
import { planFirstDeployment } from "./agent-client";

describe("agent-client", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("requests a first-deployment dry-run plan", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          profile: "private-dev",
          mode: "dry_run",
          steps: [{ name: "validate_compose_config", command: "docker compose -f deploy/compose/compose.private-dev.yaml config" }],
          requires_confirmation: true
        }),
        { headers: { "Content-Type": "application/json" } }
      )
    );

    const plan = await planFirstDeployment({ profile: "private-dev", compose_file: "deploy/compose/compose.private-dev.yaml" });

    expect(plan.mode).toBe("dry_run");
    expect(plan.requires_confirmation).toBe(true);
    expect(plan.steps[0].name).toBe("validate_compose_config");
    expect(globalThis.fetch).toHaveBeenCalledWith(
      "/v1/agent/deployments/first-run:plan",
      expect.objectContaining({ method: "POST" })
    );
  });
});

