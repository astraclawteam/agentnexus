import { developmentFixtures, type ConsoleOverview, type Locale } from "./console-data";

export type SetupStatus = {
  state: "unconfigured" | "configured_without_org" | "org_preview_ready" | "configured" | "api_unavailable" | string;
  enterprise_id: string;
  enterprise_name: string;
  admin_user_id: string;
  secret_provider: {
    mode: string;
    writable: boolean;
    accepted_ref_prefixes: string[];
  };
  checklist?: Array<{
    key: string;
    status: string;
    required: boolean;
    title: string;
    action: string;
    message?: string;
  }>;
  services: Record<string, string>;
  next_required_actions: string[];
};

export type SetupEnvironment = {
  overall_status: string;
  checks: Array<{ key: string; status: string; message: string; fix?: string }>;
  generated_at?: string;
};

export type EnterpriseSetupRequest = {
  enterprise_id: string;
  enterprise_name: string;
  admin_user_id: string;
  environment_label: string;
};

export type EnterpriseSetupResponse = {
  enterprise_id: string;
  enterprise_name: string;
  state: string;
};

export type SecretRefsValidateRequest = {
  refs: Record<string, string>;
};

export type SecretRefsValidateResponse = {
  valid: boolean;
  results: Record<string, { resolved: boolean; error?: string }>;
};

export type OrgImportPreviewRequest = {
  enterprise_id: string;
  provider: string;
  base_url: string;
  departments_path: string;
  employees_path: string;
  token_ref?: string;
  credential_ref?: string;
};

export type OrgImportPreviewResponse = {
  provider: string;
  snapshot_hash: string;
  department_count: number;
  employee_count: number;
  membership_count: number;
  requires_confirmation: boolean;
  conflicts: unknown[];
};

export type OrgImportConfirmRequest = {
  enterprise_id: string;
  provider: string;
  snapshot_hash: string;
  human_confirmation_id: string;
};

export type OrgImportConfirmResponse = {
  enterprise_id: string;
  org_version_id: string;
  imported_departments: number;
  imported_employees: number;
  imported_memberships: number;
};

export type AgentTool = {
  name: string;
  description: string;
};

export type StartAgentRunRequest = {
  enterprise_id: string;
  actor_user_id: string;
  request_id: string;
  trace_id: string;
  goal: string;
};

export type StartAgentRunResponse = {
  agent_run_id: string;
  task_run_id: string;
  status: string;
  tools: AgentTool[];
};

export type AgentRunMessageRequest = {
  enterprise_id: string;
  message: string;
};

export type AgentRunMessageResponse = {
  agent_run_id: string;
  step_id: string;
  status: string;
};

async function readJSON<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(`request failed with status ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function loadSetupStatus(): Promise<SetupStatus> {
  return readJSON<SetupStatus>(await fetch("/api/setup/status", { headers: { Accept: "application/json" } }));
}

export async function loadSetupEnvironment(): Promise<SetupEnvironment> {
  return readJSON<SetupEnvironment>(await fetch("/api/setup/environment", { headers: { Accept: "application/json" } }));
}

export async function saveEnterpriseSetup(input: EnterpriseSetupRequest): Promise<EnterpriseSetupResponse> {
  return readJSON<EnterpriseSetupResponse>(
    await fetch("/api/setup/enterprise", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(input)
    })
  );
}

export async function validateSecretRefs(input: SecretRefsValidateRequest): Promise<SecretRefsValidateResponse> {
  return readJSON<SecretRefsValidateResponse>(
    await fetch("/api/setup/secrets/validate", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(input)
    })
  );
}

export async function previewOrgImport(input: OrgImportPreviewRequest): Promise<OrgImportPreviewResponse> {
  return readJSON<OrgImportPreviewResponse>(
    await fetch("/api/org/import/preview", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(input)
    })
  );
}

export async function confirmOrgImport(input: OrgImportConfirmRequest): Promise<OrgImportConfirmResponse> {
  return readJSON<OrgImportConfirmResponse>(
    await fetch("/api/org/import/confirm", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(input)
    })
  );
}

export async function loadLiveConsoleOverview(locale: Locale, enterpriseID: string): Promise<ConsoleOverview> {
  const url = new URL("/api/console/overview", window.location.origin);
  url.searchParams.set("locale", locale);
  url.searchParams.set("enterprise_id", enterpriseID);
  return readJSON<ConsoleOverview>(await fetch(url, { headers: { Accept: "application/json" } }));
}

export async function loadDemoConsoleOverview(locale: Locale): Promise<ConsoleOverview> {
  try {
    const url = new URL("/api/console/overview", window.location.origin);
    url.searchParams.set("locale", locale);
    url.searchParams.set("demo", "true");
    return await readJSON<ConsoleOverview>(await fetch(url, { headers: { Accept: "application/json" } }));
  } catch {
    return developmentFixtures[locale];
  }
}

export async function startAgentRun(input: StartAgentRunRequest): Promise<StartAgentRunResponse> {
  return readJSON<StartAgentRunResponse>(
    await fetch("/v1/agent/runs", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(input)
    })
  );
}

export async function sendAgentRunMessage(runID: string, input: AgentRunMessageRequest): Promise<AgentRunMessageResponse> {
  return readJSON<AgentRunMessageResponse>(
    await fetch(`/v1/agent/runs/${encodeURIComponent(runID)}/messages`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(input)
    })
  );
}

export const defaultSetupAPI = {
  saveEnterpriseSetup,
  loadSetupEnvironment,
  validateSecretRefs,
  previewOrgImport,
  confirmOrgImport
};

export const defaultAgentAPI = {
  startAgentRun,
  sendAgentRunMessage
};
