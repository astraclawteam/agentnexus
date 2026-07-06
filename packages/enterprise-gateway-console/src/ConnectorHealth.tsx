const connectors = ["File storage", "Knowledge base", "CRM readonly"];

export function ConnectorHealth() {
  return (
    <section className="panel health">
      <div className="panel-head">
        <h2>Connector Health</h2>
        <span>3 online</span>
      </div>
      {connectors.map((connector) => (
        <div className="health-row" key={connector}>
          <span className="dot" />
          <span>{connector}</span>
          <strong>healthy</strong>
        </div>
      ))}
    </section>
  );
}
