import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AgentNexusDashboard } from "./AgentNexusDashboard";
import { developmentFixtures } from "./console-data";

describe("AgentNexusDashboard", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders first-run setup instead of demo metrics when gateway API is unconfigured", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/api/setup/status")) {
        return new Response(
          JSON.stringify({
            state: "unconfigured",
            enterprise_id: "",
            enterprise_name: "",
            admin_user_id: "",
            secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
            services: { gateway_api: "ready", gateway_agent: "unknown", postgres: "not_configured", nats: "not_configured" },
            next_required_actions: ["create_enterprise", "configure_secret_refs", "import_org"]
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    });

    render(<AgentNexusDashboard />);

    expect(await screen.findByRole("heading", { name: "初始化企业租户" })).toBeInTheDocument();
    expect(screen.getByText("企业租户")).toBeInTheDocument();
    expect(screen.getByText("组织导入")).toBeInTheDocument();
    expect(screen.queryByText("1,284")).not.toBeInTheDocument();
    expect(screen.queryByText("3,642")).not.toBeInTheDocument();
  });

  it("switches dashboard language in API unavailable demo fallback", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    render(<AgentNexusDashboard />);

    fireEvent.click(screen.getByRole("button", { name: "EN" }));

    expect(await screen.findByRole("heading", { name: "Enterprise Agent Command Center" })).toBeInTheDocument();
    expect(screen.getByText("Development fixture")).toBeInTheDocument();
    expect(screen.getAllByText("Example Enterprise (local dev)").length).toBeGreaterThan(0);
    expect(screen.getByPlaceholderText("Search employees, systems, policies, audit IDs")).toBeInTheDocument();
  });

  it("renders live API overview when setup is configured", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/api/setup/status")) {
        return new Response(
          JSON.stringify({
            state: "configured",
            enterprise_id: "ent_dev",
            enterprise_name: "Live Enterprise",
            admin_user_id: "admin_dev",
            secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
            checklist: [
              {
                key: "connector_verification",
                status: "recommended",
                required: false,
                title: "Verify connector runtime",
                action: "run_connector_smoke",
                message: "Validate one connector before production use."
              }
            ],
            services: { gateway_api: "ready" },
            next_required_actions: []
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.includes("/api/console/overview")) {
        return new Response(
          JSON.stringify({
            ...developmentFixtures.en,
            state: "configured",
            source: {
              kind: "api_live",
              label: "Gateway API",
              detail: "Live setup-aware overview",
              updatedAt: "2026-07-06T00:00:00+08:00"
            },
            enterprise: "Live Enterprise",
            resourceMap: {
              ...developmentFixtures.en.resourceMap,
              nodes: {
                core: ["Enterprise IAM", "1 users"],
                source: ["Organization source", "1 departments"]
              }
            }
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    });

    render(<AgentNexusDashboard />);

    expect(await screen.findByText("Gateway API")).toBeInTheDocument();
    expect(screen.getAllByText("Live Enterprise").length).toBeGreaterThan(0);
    expect(screen.getByText("Setup checklist")).toBeInTheDocument();
    expect(screen.getByText("Verify connector runtime")).toBeInTheDocument();
  });

  it("shows sync org as a visible setup action", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/api/setup/status")) {
        return new Response(
          JSON.stringify({
            state: "configured",
            enterprise_id: "ent_dev",
            enterprise_name: "顺视智能制造集团",
            admin_user_id: "admin_dev",
            secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
            services: { gateway_api: "ready" },
            next_required_actions: []
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.includes("/api/console/overview")) {
        return new Response(
          JSON.stringify({
            ...developmentFixtures.en,
            state: "configured",
            source: {
              kind: "api_live",
              label: "Gateway API 实时数据",
              detail: "来自已配置企业状态的实时总览数据。",
              updatedAt: "2026-07-06T00:00:00+08:00"
            },
            enterprise: "顺视智能制造集团",
            topbar: {
              ...developmentFixtures.en.topbar,
              sync: "同步组织"
            }
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    });

    render(<AgentNexusDashboard />);

    expect(await screen.findByRole("button", { name: "同步组织" })).toBeInTheDocument();
    expect(screen.getByText("同步组织")).toBeInTheDocument();
  });
  it("opens the demo dashboard from the setup flow reached through sync org", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/api/setup/status")) {
        return new Response(
          JSON.stringify({
            state: "configured_without_org",
            enterprise_id: "ent_dev",
            enterprise_name: "Local Enterprise",
            admin_user_id: "admin_dev",
            secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
            services: { gateway_api: "ready" },
            next_required_actions: ["import_org"]
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.includes("/api/console/overview")) {
        return new Response(
          JSON.stringify({
            ...developmentFixtures.en,
            topbar: {
              ...developmentFixtures.en.topbar,
              sync: "Sync org"
            }
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    });

    render(<AgentNexusDashboard />);

    fireEvent.click(await screen.findByRole("button", { name: "Sync org" }));
    fireEvent.click(await screen.findByRole("button", { name: "查看演示仪表盘（开发模式）" }));

    expect(await screen.findByText("Demo mode / 演示数据")).toBeInTheDocument();
    expect(screen.getByText("仅用于开发演示，不会标记系统已配置。")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "返回首次配置" }));

    expect(await screen.findByRole("button", { name: "查看演示仪表盘（开发模式）" })).toBeInTheDocument();
  });

  it("returns from the setup flow reached through sync org back to the live console", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/api/setup/status")) {
        return new Response(
          JSON.stringify({
            state: "configured_without_org",
            enterprise_id: "ent_dev",
            enterprise_name: "Local Enterprise",
            admin_user_id: "admin_dev",
            secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
            services: { gateway_api: "ready" },
            next_required_actions: ["import_org"]
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      if (url.includes("/api/console/overview")) {
        return new Response(
          JSON.stringify({
            ...developmentFixtures.en,
            title: "Live Console",
            topbar: {
              ...developmentFixtures.en.topbar,
              sync: "Sync org"
            }
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    });

    render(<AgentNexusDashboard />);

    fireEvent.click(await screen.findByRole("button", { name: "Sync org" }));

    expect(await screen.findByRole("button", { name: "返回实时控制台" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "返回实时控制台" }));

    expect(await screen.findByRole("heading", { name: "Live Console" })).toBeInTheDocument();
    expect(screen.queryByText("Demo mode / 演示数据")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sync org" })).toBeInTheDocument();
  });
});
