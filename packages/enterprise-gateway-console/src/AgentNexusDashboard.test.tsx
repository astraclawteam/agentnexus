import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AgentNexusDashboard } from "./AgentNexusDashboard";
import { developmentFixtures } from "./console-data";

describe("AgentNexusDashboard", () => {
  it("renders the enterprise admin gateway prototype regions", async () => {
    render(<AgentNexusDashboard />);

    expect(await screen.findByRole("heading", { name: "企业智能行政中枢" })).toBeInTheDocument();
    expect(screen.getByText("本地开发数据")).toBeInTheDocument();
    expect(screen.getAllByText("示例企业（本地开发）").length).toBeGreaterThan(0);
    expect(screen.getByText("当前企业")).toBeInTheDocument();
    expect(screen.getByText("企业资源地图")).toBeInTheDocument();
    expect(screen.getByText("最近 Access Tickets")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "连接器健康" })).toBeInTheDocument();
    expect(screen.getByLabelText("打开 Agent 对话")).toBeInTheDocument();
  });

  it("switches dashboard language", async () => {
    render(<AgentNexusDashboard />);

    fireEvent.click(screen.getByRole("button", { name: "EN" }));

    expect(await screen.findByRole("heading", { name: "Enterprise Agent Command Center" })).toBeInTheDocument();
    expect(screen.getByText("Development fixture")).toBeInTheDocument();
    expect(screen.getAllByText("Example Enterprise (local dev)").length).toBeGreaterThan(0);
    expect(screen.getByPlaceholderText("Search employees, systems, policies, audit IDs")).toBeInTheDocument();
  });

  it("renders API overview when the console endpoint is available", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          ...developmentFixtures.zh,
          source: {
            kind: "api",
            label: "Gateway API",
            detail: "gateway-api 返回的开发总览数据。",
            updatedAt: "2026-07-06T00:00:00+08:00"
          },
          enterprise: "示例企业（Gateway API）"
        }),
        { headers: { "Content-Type": "application/json" } }
      );

    try {
      render(<AgentNexusDashboard />);

      expect(await screen.findByText("Gateway API")).toBeInTheDocument();
      expect(screen.getAllByText("示例企业（Gateway API）").length).toBeGreaterThan(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
