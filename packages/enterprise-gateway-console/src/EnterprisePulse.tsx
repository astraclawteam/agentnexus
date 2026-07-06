const items = ["Gateway runtime", "Policy guardrails", "Connector agent", "Audit chain"];

export function EnterprisePulse() {
  return (
    <aside className="pulse">
      <div className="brand">AgentNexus</div>
      <nav>
        {items.map((item) => (
          <button className="pulse-item" key={item}>
            <span className="dot" />
            {item}
          </button>
        ))}
      </nav>
      <div className="pulse-footer">
        <strong>Enterprise Pulse</strong>
        <span>SaaS dev</span>
      </div>
    </aside>
  );
}
