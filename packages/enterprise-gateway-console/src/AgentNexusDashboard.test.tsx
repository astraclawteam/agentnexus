import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AgentNexusDashboard } from "./AgentNexusDashboard";
import { developmentFixtures } from "./console-data";

describe("AgentNexusDashboard", () => {
  it("depends on the published Xiaozhi family UI boundary", () => {
    const source = readFileSync("src/AgentNexusDashboard.tsx", "utf8");
    const retiredPackage = ["@agentnexus", "claw-runtime-ui"].join("/");

    expect(source).toContain("@xiaozhiclaw/runtime-ui");
    expect(source).not.toContain(retiredPackage);
  });

  it("keeps all shared UI imports on the family package and loads its stylesheet once", () => {
    const sources = readdirSync("src")
      .filter((name) => name.endsWith(".tsx") && !name.endsWith(".test.tsx"))
      .map((name) => readFileSync(`src/${name}`, "utf8"))
      .join("\n");
    const retiredPackage = ["@agentnexus", "claw-runtime-ui"].join("/");

    expect(sources).not.toContain(retiredPackage);
    expect(sources.match(/@xiaozhiclaw\/runtime-ui\/styles\.css/g)).toHaveLength(1);
  });

  it("adapts at 1179px without imposing a whole-page minimum width", () => {
    const css = readFileSync("src/styles.css", "utf8");

    expect(css).not.toMatch(/body\s*\{[^}]*min-width:\s*1180px/s);
    expect(css).toContain("@media (max-width: 1179px)");
    expect(css).toMatch(/\.workspace\s*\{[^}]*min-width:\s*0/s);
    expect(css).toMatch(/\.ticket-table\s*\{[^}]*overflow-x:\s*auto/s);
    expect(css).toMatch(/\.agent-chat-panel\s*\{[^}]*calc\(100vw - 48px\)/s);
  });

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

  it("exposes the selected locale as a pressed state", async () => {
    const user = userEvent.setup();
    render(<AgentNexusDashboard />);

    const zh = screen.getByRole("button", { name: "\u4e2d\u6587" });
    const en = screen.getByRole("button", { name: "EN" });
    expect(zh).toHaveAttribute("aria-pressed", "true");
    expect(en).toHaveAttribute("aria-pressed", "false");

    await user.click(en);

    expect(zh).toHaveAttribute("aria-pressed", "false");
    expect(en).toHaveAttribute("aria-pressed", "true");
  });

  it("keeps focus inside the accessible Agent drawer and restores the launcher on Escape", async () => {
    const user = userEvent.setup();
    render(<AgentNexusDashboard />);

    await user.click(screen.getByRole("button", { name: "EN" }));
    const launcher = await screen.findByRole("button", { name: "Open Agent chat" });
    await user.click(launcher);

    const dialog = screen.getByRole("dialog", { name: "Gateway Agent" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    expect(document.querySelector("main")?.closest('[aria-hidden="true"]')).not.toBeNull();
    expect(document.body.style.pointerEvents).toBe("none");

    for (let index = 0; index < 8; index += 1) {
      await user.tab();
      expect(dialog).toContainElement(document.activeElement as HTMLElement);
    }

    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog", { name: "Gateway Agent" })).not.toBeInTheDocument();
    expect(launcher).toHaveFocus();
  });

  it("keeps quick prompts, typing, trimmed send, messages, and draft state controlled by the Console", async () => {
    const user = userEvent.setup();
    render(<AgentNexusDashboard />);

    await user.click(screen.getByRole("button", { name: "EN" }));
    await user.click(await screen.findByRole("button", { name: "Open Agent chat" }));
    await user.click(screen.getByRole("button", { name: "Generate MES connector" }));

    const prompt = screen.getByPlaceholderText("Type a request, for example: connect a new OA receipt API");
    expect(prompt).toHaveValue("Generate MES connector");

    await user.clear(prompt);
    await user.type(prompt, "   assess fields   ");
    await user.click(screen.getByRole("button", { name: "Send" }));

    expect(screen.getByText("Request captured: assess fields")).toBeInTheDocument();
    expect(prompt).toHaveValue("");
  });

  it("keeps the controlled Agent chat copy in sync with the selected language", async () => {
    render(<AgentNexusDashboard />);

    fireEvent.click(screen.getByRole("button", { name: "EN" }));
    fireEvent.click(await screen.findByRole("button", { name: "Open Agent chat" }));

    expect(screen.getByText(/I can create connector drafts/)).toBeInTheDocument();
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
