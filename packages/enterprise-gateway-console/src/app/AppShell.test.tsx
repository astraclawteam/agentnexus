import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppShell } from "./AppShell";

describe("AppShell", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows an offline-first blocked screen when gateway-api is unreachable", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));

    render(<AppShell />);

    expect(await screen.findByRole("heading", { name: "本地服务未连接" })).toBeInTheDocument();
    expect(screen.getByText("请先启动 gateway-api，然后重新检查。")).toBeInTheDocument();
    expect(screen.queryByText("1,284")).not.toBeInTheDocument();
    expect(screen.queryByText("3,642")).not.toBeInTheDocument();
  });

  it("opens a clearly labeled dev demo dashboard from first-run without marking setup configured", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes("/api/setup/status")) {
        return new Response(
          JSON.stringify({
            state: "unconfigured",
            enterprise_id: "",
            enterprise_name: "",
            admin_user_id: "",
            secret_provider: { mode: "env", writable: false, accepted_ref_prefixes: ["secret://env/"] },
            services: { gateway_api: "ready" },
            next_required_actions: ["create_enterprise"]
          }),
          { headers: { "Content-Type": "application/json" } }
        );
      }
      return new Response("not found", { status: 404 });
    });

    render(<AppShell />);

    fireEvent.click(await screen.findByRole("button", { name: "查看演示仪表盘（开发模式）" }));

    expect(await screen.findByText("Demo mode / 演示数据")).toBeInTheDocument();
    expect(screen.getByText("仅用于开发演示，不会标记系统已配置。")).toBeInTheDocument();
    expect(screen.getByText("返回首次配置")).toBeInTheDocument();
    await waitFor(() => {
      expect(fetchSpy.mock.calls.some(([, init]) => init && init.method && init.method !== "GET")).toBe(false);
    });
  });
});
