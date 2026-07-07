import { useEffect, useState } from "react";
import { AgentNexusDashboard } from "../AgentNexusDashboard";
import { FirstRunSetup } from "../FirstRunSetup";
import { defaultSetupAPI, loadSetupStatus, type SetupStatus } from "../setup-api";
import { deriveAppMode, type AppMode } from "./app-mode";

export function AppShell() {
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [showDemoDashboard, setShowDemoDashboard] = useState(false);

  useEffect(() => {
    let cancelled = false;

    setLoadError(null);
    void loadSetupStatus()
      .then((status) => {
        if (!cancelled) {
          setSetupStatus(status);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setSetupStatus(null);
          setLoadError(error);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  const mode: AppMode = deriveAppMode(setupStatus, loadError);

  if (mode === "api_unavailable") {
    return <APIUnavailableScreen onRetry={() => setReloadKey((key) => key + 1)} />;
  }

  if (showDemoDashboard) {
    return <AgentNexusDashboard forceDemo onExitDemo={() => setShowDemoDashboard(false)} />;
  }

  if (mode === "setup_required") {
    return (
      <FirstRunSetup
        locale="zh"
        api={defaultSetupAPI}
        onOpenDemo={() => setShowDemoDashboard(true)}
        onComplete={() => {
          setReloadKey((key) => key + 1);
        }}
      />
    );
  }

  return <AgentNexusDashboard />;
}

function APIUnavailableScreen({ onRetry }: { onRetry: () => void }) {
  return (
    <main className="api-unavailable-shell" lang="zh-CN">
      <section className="api-unavailable-panel" aria-labelledby="api-unavailable-title">
        <p className="first-run-kicker">AgentNexus 离线部署</p>
        <h1 id="api-unavailable-title">本地服务未连接</h1>
        <p>请先启动 gateway-api，然后重新检查。</p>
        <ul>
          <li>确认 gateway-api 监听在 127.0.0.1:8080。</li>
          <li>确认 Vite 代理可以访问 /api/setup/status。</li>
          <li>如果使用 Docker Compose，请先启动 private-dev profile。</li>
        </ul>
        <button className="primary-button" type="button" onClick={onRetry}>
          重新检查
        </button>
      </section>
    </main>
  );
}
