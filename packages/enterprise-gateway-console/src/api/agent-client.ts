import { readJSON } from "./http";

export type FirstDeploymentPlanRequest = {
  profile: string;
  compose_file: string;
};

export type DeploymentPlan = {
  profile: string;
  mode: "dry_run" | string;
  steps: Array<{ name: string; command?: string; description?: string }>;
  requires_confirmation: boolean;
};

export async function planFirstDeployment(input: FirstDeploymentPlanRequest): Promise<DeploymentPlan> {
  return readJSON<DeploymentPlan>(
    await fetch("/v1/agent/deployments/first-run:plan", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(input)
    })
  );
}

