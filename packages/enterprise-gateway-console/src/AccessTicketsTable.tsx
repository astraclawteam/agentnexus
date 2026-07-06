const rows = [
  ["TCK-1042", "Legal knowledge", "need_external_receipt"],
  ["TCK-1041", "Finance files", "allow_with_masking"],
  ["TCK-1040", "CRM account", "deny"]
];

export function AccessTicketsTable() {
  return (
    <section className="panel tickets">
      <div className="panel-head">
        <h2>Access Tickets</h2>
        <span>live</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Ticket</th>
            <th>Resource</th>
            <th>Decision</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([ticket, resource, decision]) => (
            <tr key={ticket}>
              <td>{ticket}</td>
              <td>{resource}</td>
              <td>
                <span className="status">{decision}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
