import { useEffect, useState } from "react";
import { Button, Input } from "@agentnexus/claw-runtime-ui";
import { AccessTicketsTable } from "./AccessTicketsTable";
import { ConnectorHealth } from "./ConnectorHealth";
import { developmentFixtures, loadConsoleOverview, localeNames, type ConsoleOverview, type Locale } from "./console-data";
import { EnterprisePulse } from "./EnterprisePulse";
import { FirstRunSetup } from "./FirstRunSetup";
import { GatewayAgentLauncher } from "./GatewayAgentLauncher";
import { ResourceMap } from "./ResourceMap";
import { defaultSetupAPI, loadLiveConsoleOverview, loadSetupStatus, type SetupStatus } from "./setup-api";

type AgentNexusDashboardProps = {
  forceDemo?: boolean;
  onExitDemo?: () => void;
};

export function AgentNexusDashboard({ forceDemo = false, onExitDemo }: AgentNexusDashboardProps) {
  const [locale, setLocale] = useState<Locale>("zh");
  const [overview, setOverview] = useState<ConsoleOverview>(developmentFixtures.zh);
  const [setupStatus, setSetupStatus] = useState<SetupStatus | null>(null);
  const [showSetup, setShowSetup] = useState(false);
  const [showSetupDemo, setShowSetupDemo] = useState(false);
  const [smokeStatus, setSmokeStatus] = useState("");
  const isDemoMode = forceDemo || showSetupDemo;

  useEffect(() => {
    let cancelled = false;

    setOverview(developmentFixtures[locale]);
    setSetupStatus(null);
    if (isDemoMode) {
      return () => {
        cancelled = true;
      };
    }

    void loadSetupStatus()
      .then(async (status) => {
        if (cancelled) {
          return;
        }
        setSetupStatus(status);
        if (status.state === "unconfigured" || !status.enterprise_id) {
          return;
        }
        const nextOverview = await loadLiveConsoleOverview(locale, status.enterprise_id);
        if (!cancelled) {
          setOverview(nextOverview);
        }
      })
      .catch(() => {
        void loadConsoleOverview(locale).then((nextOverview) => {
          if (!cancelled) {
            setOverview(nextOverview);
          }
        });
      });

    return () => {
      cancelled = true;
    };
  }, [locale, isDemoMode]);

  async function reloadAfterSetup() {
    const status = await loadSetupStatus();
    setSetupStatus(status);
    if (status.enterprise_id) {
      setOverview(await loadLiveConsoleOverview(locale, status.enterprise_id));
    }
  }

  if (!isDemoMode && setupStatus?.state === "unconfigured") {
    return <FirstRunSetup locale={locale} api={defaultSetupAPI} onComplete={reloadAfterSetup} />;
  }
  if (showSetup) {
    return (
      <FirstRunSetup
        locale={locale}
        api={defaultSetupAPI}
        onComplete={async () => {
          setShowSetup(false);
          await reloadAfterSetup();
        }}
        onOpenDemo={() => {
          setShowSetup(false);
          setShowSetupDemo(true);
        }}
        onExitSetup={() => setShowSetup(false)}
      />
    );
  }

  const t = overview;

  return (
    <main className="console-shell" lang={locale === "zh" ? "zh-CN" : "en"}>
      <EnterprisePulse copy={t} />
      <section className="workspace">
        <header className="topbar">
          <label className="company-switcher">
            <span className="icon icon-building" aria-hidden="true" />
            <span className="sr-only">{t.topbar.enterpriseLabel}</span>
            <select aria-label={t.topbar.enterpriseLabel}>
              <option>{t.enterprise}</option>
              <option>{t.enterpriseAlt}</option>
            </select>
          </label>
          <label className="topbar-search">
            <span className="icon icon-search" aria-hidden="true" />
            <Input type="search" aria-label={t.topbar.search} placeholder={t.topbar.search} />
          </label>
          <button className="topbar-action sync-action" type="button" onClick={() => setShowSetup(true)}>
            <span className="icon icon-sync" aria-hidden="true" />
            <span>{t.topbar.sync}</span>
          </button>
          <button className="icon-button" title={t.topbar.notifications} aria-label={t.topbar.notifications}>
            <span className="icon icon-bell" aria-hidden="true" />
            <span className="badge-dot" />
          </button>
          <div className={`data-source-chip source-${t.source.kind}`} aria-label={t.source.detail}>
            <span className={`dot ${t.source.kind === "api" ? "dot-ok" : "dot-warn"}`} aria-hidden="true" />
            <span>{t.source.label}</span>
          </div>
          <div className="locale-switch" role="group" aria-label="Language">
            {(Object.keys(localeNames) as Locale[]).map((nextLocale) => (
              <button
                className={nextLocale === locale ? "is-selected" : ""}
                key={nextLocale}
                type="button"
                onClick={() => setLocale(nextLocale)}
              >
                {localeNames[nextLocale]}
              </button>
            ))}
          </div>
          <div className="avatar" aria-label={t.topbar.avatar}>
            {t.topbar.avatar}
          </div>
        </header>

        <section className="page-head">
          <div>
            <h1>{t.title}</h1>
            <p>{t.subtitle}</p>
            <p className="source-note">{t.source.detail}</p>
          </div>
          <div className="head-actions">
            <Button className="ghost-button" variant="ghost" disabled title="Audit export API is not implemented yet">
              <span className="icon icon-download" aria-hidden="true" />
              {t.topbar.exportAudit}
            </Button>
          </div>
        </section>

        {isDemoMode ? (
          <section className="demo-mode-banner" aria-label="Demo mode">
            <div>
              <strong>Demo mode / 演示数据</strong>
              <span>仅用于开发演示，不会标记系统已配置。</span>
            </div>
            {onExitDemo || showSetupDemo ? (
              <button
                type="button"
                onClick={() => {
                  if (onExitDemo) {
                    onExitDemo();
                    return;
                  }
                  setShowSetupDemo(false);
                  setShowSetup(true);
                }}
              >
                返回首次配置
              </button>
            ) : null}
          </section>
        ) : null}

        {setupStatus?.checklist?.length ? (
          <section className="setup-checklist" aria-label="Setup checklist">
            <div className="section-title">
              <h2>Setup checklist</h2>
              <span>{setupStatus.state}</span>
            </div>
            <div className="setup-checklist-grid">
              {setupStatus.checklist.map((item) => (
                <article className={`setup-checklist-item status-${item.status}`} key={item.key}>
                  <span>{item.required ? "Required" : "Recommended"}</span>
                  <strong>{item.title}</strong>
                  {item.message ? <p>{item.message}</p> : null}
                </article>
              ))}
            </div>
          </section>
        ) : null}

        <section className="metrics" aria-label="Gateway metrics">
          {t.metrics.map(([label, value, note, tone]) => (
            <article className="metric-card" key={label}>
              <div className="metric-label">{label}</div>
              <div className="metric-value">{value}</div>
              <div className={`metric-foot ${tone}`}>{note}</div>
            </article>
          ))}
        </section>

        <section className="main-grid single">
          <ResourceMap copy={t.resourceMap} />
        </section>

        <section className="lower-grid">
          <AccessTicketsTable copy={t.tickets} />
          <ConnectorHealth copy={t.connectors} smokeStatus={smokeStatus} onSmoke={() => setSmokeStatus("Connector smoke uses first-run setup until an instance is selected.")} />
        </section>
      </section>

      <GatewayAgentLauncher copy={t.agent} enterpriseID={setupStatus?.enterprise_id || "ent_dev"} actorUserID={setupStatus?.admin_user_id || "admin_dev"} />
    </main>
  );
}
