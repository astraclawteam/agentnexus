import { readJSON } from "./http";

export type SetupSession = {
  mode: string;
  actor_user_id: string;
  secure: boolean;
  message?: string;
};

export type SetupEnvironmentCheck = {
  key: string;
  status: string;
  message: string;
  fix?: string;
};

export type SetupEnvironment = {
  overall_status: string;
  checks: SetupEnvironmentCheck[];
  generated_at?: string;
};

export type SetupChecklistItem = {
  key: string;
  status: string;
  required: boolean;
  title: string;
  action: string;
  message?: string;
};

export type SetupStatus = {
  state: "unconfigured" | "configured_without_org" | "org_preview_ready" | "configured" | "api_unavailable" | string;
  enterprise_id: string;
  enterprise_name: string;
  admin_user_id: string;
  environment_label?: string;
  session?: SetupSession;
  secret_provider: {
    mode: string;
    writable: boolean;
    accepted_ref_prefixes: string[];
  };
  environment?: SetupEnvironment;
  checklist?: SetupChecklistItem[];
  services: Record<string, string>;
  next_required_actions: string[];
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
  results: Record<string, { resolved: boolean; code?: string; error?: string; fix?: string }>;
};

export async function loadSetupStatus(): Promise<SetupStatus> {
  return readJSON<SetupStatus>(await fetch("/api/setup/status", { headers: { Accept: "application/json" } }));
}

export async function loadSetupEnvironment(): Promise<SetupEnvironment> {
  return readJSON<SetupEnvironment>(await fetch("/api/setup/environment", { headers: { Accept: "application/json" } }));
}

export async function loadSetupSession(): Promise<SetupSession> {
  return readJSON<SetupSession>(await fetch("/api/setup/session", { headers: { Accept: "application/json" } }));
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

