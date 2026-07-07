import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FirstRunSetup } from "./FirstRunSetup";

describe("FirstRunSetup", () => {
  it("renders complete Chinese first-run copy without mojibake", () => {
    const api = {
      saveEnterpriseSetup: vi.fn(),
      loadSetupEnvironment: vi.fn(),
      validateSecretRefs: vi.fn(),
      previewOrgImport: vi.fn(),
      confirmOrgImport: vi.fn()
    };

    render(<FirstRunSetup locale="zh" api={api} onComplete={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "初始化企业租户" })).toBeInTheDocument();
    expect(screen.getByText("企业租户")).toBeInTheDocument();
    expect(screen.getByText("密钥引用")).toBeInTheDocument();
    expect(screen.getByText("组织导入")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "保存租户并继续" })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/[�]|鍒|浼|绉|閰|瀵|杩/);
  });

  it("marks first-run fields as editable controls with visible affordance hooks", () => {
    const api = {
      saveEnterpriseSetup: vi.fn(),
      loadSetupEnvironment: vi.fn(),
      validateSecretRefs: vi.fn(),
      previewOrgImport: vi.fn(),
      confirmOrgImport: vi.fn()
    };

    render(<FirstRunSetup locale="en" api={api} onComplete={vi.fn()} />);

    expect(screen.getByLabelText("Enterprise tenant ID")).toHaveClass("first-run-input");
    expect(screen.getByLabelText("Enterprise tenant name")).toHaveClass("first-run-input");
    expect(screen.getByLabelText("Tenant admin user ID")).toHaveClass("first-run-input");
    expect(screen.getAllByText("Editable before saving").length).toBeGreaterThanOrEqual(3);
  });

  it("guides a SaaS enterprise tenant through setup, org preview, and live console entry", async () => {
    const onComplete = vi.fn();
    const api = {
      saveEnterpriseSetup: vi.fn().mockResolvedValue({
        enterprise_id: "ent_dev",
        enterprise_name: "Local Development Enterprise",
        state: "configured_without_org"
      }),
      loadSetupEnvironment: vi.fn().mockResolvedValue({
        overall_status: "warning",
        checks: [{ key: "gateway_api", status: "ready", message: "gateway-api is ready" }]
      }),
      validateSecretRefs: vi.fn().mockResolvedValue({
        valid: true,
        results: {
          llmrouter_api_key: { resolved: true },
          oa_token: { resolved: true },
          connector_credential: { resolved: true }
        }
      }),
      previewOrgImport: vi.fn().mockResolvedValue({
        provider: "oa_http",
        snapshot_hash: "hash_1",
        department_count: 1,
        employee_count: 1,
        membership_count: 1,
        requires_confirmation: false,
        conflicts: []
      }),
      confirmOrgImport: vi.fn().mockResolvedValue({
        enterprise_id: "ent_dev",
        org_version_id: "version_1",
        imported_departments: 1,
        imported_employees: 1,
        imported_memberships: 1
      })
    };

    render(<FirstRunSetup locale="en" api={api} onComplete={onComplete} />);

    expect(screen.getByRole("heading", { name: "Set up an enterprise tenant" })).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument();
    expect(screen.getByText("Enterprise tenant")).toBeInTheDocument();
    expect(screen.getByText("Secret refs")).toBeInTheDocument();
    expect(screen.getByText("Organization import")).toBeInTheDocument();
    expect(screen.getByText("Live console")).toBeInTheDocument();
    expect(screen.getByText("This creates one tenant workspace for a company. Organization data, connectors, policy, and Agent runs will be scoped to this enterprise.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save tenant and continue" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Validate refs and continue" })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Enterprise tenant ID"), { target: { value: "ent_dev" } });
    fireEvent.change(screen.getByLabelText("Enterprise tenant name"), { target: { value: "Local Development Enterprise" } });
    fireEvent.change(screen.getByLabelText("Tenant admin user ID"), { target: { value: "admin_dev" } });
    fireEvent.click(screen.getByRole("button", { name: "Save tenant and continue" }));

    expect(await screen.findByRole("button", { name: "Recheck environment and continue" })).toBeInTheDocument();
    expect(screen.getByText("Confirm the local offline runtime is healthy enough before configuring credentials and organization data.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Recheck environment and continue" }));

    expect(await screen.findByRole("button", { name: "Validate refs and continue" })).toBeInTheDocument();
    expect(screen.getByText("Secret values stay outside the browser and repository. This page only validates references such as secret://env/LLMROUTER_API_KEY.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("llmrouter API key secret ref"), { target: { value: "secret://env/LLMROUTER_API_KEY" } });
    fireEvent.change(screen.getByLabelText("OA token secret ref"), { target: { value: "secret://env/AGENTNEXUS_OA_TOKEN" } });
    fireEvent.change(screen.getByLabelText("Connector credential secret ref"), { target: { value: "secret://env/AGENTNEXUS_FILE_STORAGE_TOKEN" } });
    fireEvent.click(screen.getByRole("button", { name: "Validate refs and continue" }));

    expect(await screen.findByRole("button", { name: "Preview organization data" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Base URL"), { target: { value: "http://127.0.0.1:18080" } });
    fireEvent.click(screen.getByRole("button", { name: "Preview organization data" }));

    expect(await screen.findByText("Ready to import 1 employee, 1 department, and 1 membership into this tenant.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Confirm import and enter console" }));

    await waitFor(() => expect(onComplete).toHaveBeenCalled());
    expect(api.confirmOrgImport).toHaveBeenCalledWith(
      expect.objectContaining({
        enterprise_id: "ent_dev",
        provider: "oa_http",
        snapshot_hash: "hash_1"
      })
    );
  });
});
