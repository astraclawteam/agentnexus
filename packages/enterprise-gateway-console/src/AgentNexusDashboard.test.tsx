import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AgentNexusDashboard } from "./AgentNexusDashboard";

describe("AgentNexusDashboard", () => {
  it("renders the enterprise admin gateway prototype regions", () => {
    render(<AgentNexusDashboard />);

    expect(screen.getByRole("heading", { name: "企业智能行政中枢" })).toBeInTheDocument();
    expect(screen.getByText("当前企业")).toBeInTheDocument();
    expect(screen.getByText("企业资源地图")).toBeInTheDocument();
    expect(screen.getByText("最近 Access Tickets")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "连接器健康" })).toBeInTheDocument();
    expect(screen.getByLabelText("打开 Agent 对话")).toBeInTheDocument();
  });

  it("switches dashboard language", () => {
    render(<AgentNexusDashboard />);

    fireEvent.click(screen.getByRole("button", { name: "EN" }));

    expect(screen.getByRole("heading", { name: "Enterprise Agent Command Center" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText("Search employees, systems, policies, audit IDs")).toBeInTheDocument();
  });
});
