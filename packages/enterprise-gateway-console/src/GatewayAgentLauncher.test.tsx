import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GatewayAgentLauncher } from "./GatewayAgentLauncher";

const copy = {
  open: "Open Agent chat",
  title: "Gateway Agent",
  desc: "Describe the integration, change, or issue you want to handle",
  close: "Close",
  intro: "I can create connector drafts.",
  prompts: ["Configure org import"],
  input: "Type a setup request",
  send: "Send",
  sentPrefix: "Request captured"
};

describe("GatewayAgentLauncher", () => {
  it("creates a backend agent run and displays allowed tools on first message", async () => {
    const api = {
      startAgentRun: vi.fn().mockResolvedValue({
        agent_run_id: "run_1",
        task_run_id: "run_1",
        status: "running",
        tools: [
          { name: "org_import_preview", description: "Preview org import" },
          { name: "connector_package_validate", description: "Validate connector" }
        ]
      }),
      sendAgentRunMessage: vi.fn().mockResolvedValue({
        agent_run_id: "run_1",
        step_id: "step_1",
        status: "running"
      })
    };

    render(<GatewayAgentLauncher copy={copy} enterpriseID="ent_dev" actorUserID="admin_dev" api={api} />);

    fireEvent.click(screen.getByLabelText("Open Agent chat"));
    fireEvent.change(screen.getByPlaceholderText("Type a setup request"), { target: { value: "Configure first-run setup" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));

    expect(await screen.findByText("Agent run: run_1")).toBeInTheDocument();
    expect(screen.getByText("org_import_preview")).toBeInTheDocument();
    expect(api.startAgentRun).toHaveBeenCalledWith(
      expect.objectContaining({
        enterprise_id: "ent_dev",
        actor_user_id: "admin_dev",
        goal: "Configure first-run setup"
      })
    );
  });
});
