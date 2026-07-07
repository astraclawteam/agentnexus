import type { FirstRunChecklistItem, FirstRunStatus, FirstRunStep } from "./first-run-types";

export function deriveFirstRunStep(status: FirstRunStatus): FirstRunStep {
  const checklist = status.checklist || [];

  if (status.state === "unconfigured" || !status.enterprise_id || isActive(checklist, "enterprise_tenant")) {
    return "tenant";
  }
  if (isActive(checklist, "environment_check")) {
    return "environment";
  }
  if (isActive(checklist, "secret_refs")) {
    return "secrets";
  }
  if (isActive(checklist, "organization_import")) {
    return "org";
  }
  if (isRecommended(checklist, "connector_verification")) {
    return "connectors";
  }
  if (isRecommended(checklist, "gateway_agent_dry_run")) {
    return "agent";
  }
  return "console";
}

function isActive(checklist: FirstRunChecklistItem[], key: string): boolean {
  const item = checklist.find((candidate) => candidate.key === key);
  return item?.status === "required" || item?.status === "blocked";
}

function isRecommended(checklist: FirstRunChecklistItem[], key: string): boolean {
  return checklist.find((candidate) => candidate.key === key)?.status === "recommended";
}

