export type FirstRunStep = "admin" | "tenant" | "environment" | "secrets" | "org" | "connectors" | "agent" | "console";

export type FirstRunChecklistItem = {
  key: string;
  status: string;
  required: boolean;
  title: string;
  action: string;
  message?: string;
};

export type FirstRunStatus = {
  state: string;
  enterprise_id: string;
  enterprise_name: string;
  admin_user_id: string;
  checklist?: FirstRunChecklistItem[];
};

