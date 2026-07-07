import type { SetupStatus } from "../setup-api";

export type AppMode = "api_unavailable" | "setup_required" | "configured";

export function deriveAppMode(status: SetupStatus | null, error?: unknown): AppMode {
  if (!status || error) {
    return "api_unavailable";
  }
  if (status.state === "unconfigured" || !status.enterprise_id) {
    return "setup_required";
  }
  return "configured";
}

