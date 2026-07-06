import { useEffect, useState } from "react";
import { Button, Input } from "@agentnexus/claw-runtime-ui";
import { AccessTicketsTable } from "./AccessTicketsTable";
import { ConnectorHealth } from "./ConnectorHealth";
import { developmentFixtures, loadConsoleOverview, localeNames, type ConsoleOverview, type Locale } from "./console-data";
import { EnterprisePulse } from "./EnterprisePulse";
import { GatewayAgentLauncher } from "./GatewayAgentLauncher";
import { ResourceMap } from "./ResourceMap";

export function AgentNexusDashboard() {
  const [locale, setLocale] = useState<Locale>("zh");
  const [overview, setOverview] = useState<ConsoleOverview>(developmentFixtures.zh);

  useEffect(() => {
    let cancelled = false;

    setOverview(developmentFixtures[locale]);
    void loadConsoleOverview(locale).then((nextOverview) => {
      if (!cancelled) {
        setOverview(nextOverview);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [locale]);

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
          <button className="icon-button" title={t.topbar.sync} aria-label={t.topbar.sync}>
            <span className="icon icon-sync" aria-hidden="true" />
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
            <Button className="ghost-button" variant="ghost">
              <span className="icon icon-download" aria-hidden="true" />
              {t.topbar.exportAudit}
            </Button>
          </div>
        </section>

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
          <ConnectorHealth copy={t.connectors} />
        </section>
      </section>

      <GatewayAgentLauncher copy={t.agent} />
    </main>
  );
}
