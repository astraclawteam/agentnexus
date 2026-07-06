import { Button, Input } from "@agentnexus/claw-runtime-ui";
import { AccessTicketsTable } from "./AccessTicketsTable";
import { ConnectorHealth } from "./ConnectorHealth";
import { EnterprisePulse } from "./EnterprisePulse";
import { GatewayAgentLauncher } from "./GatewayAgentLauncher";
import { ResourceMap } from "./ResourceMap";

const metrics = [
  ["Active Agents", "12", "+3 today"],
  ["Pending Access Tickets", "8", "2 urgent"],
  ["Connector Health", "97%", "1 degraded"],
  ["Audit Events", "18.4k", "hash chain ok"]
];

export function AgentNexusDashboard() {
  return (
    <main className="console-shell">
      <EnterprisePulse />
      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>AgentNexus</h1>
            <p>Enterprise gateway control plane</p>
          </div>
          <div className="topbar-actions">
            <Input aria-label="Search resources" placeholder="Search resources" />
            <Button>Launch agent</Button>
          </div>
        </header>
        <section className="metrics" aria-label="Gateway metrics">
          {metrics.map(([label, value, note]) => (
            <article className="metric" key={label}>
              <span>{label}</span>
              <strong>{value}</strong>
              <small>{note}</small>
            </article>
          ))}
        </section>
        <section className="main-grid">
          <ResourceMap />
          <GatewayAgentLauncher />
        </section>
        <section className="lower-grid">
          <AccessTicketsTable />
          <ConnectorHealth />
        </section>
      </section>
    </main>
  );
}
