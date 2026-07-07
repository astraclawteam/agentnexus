import { useState } from "react";
import { Button } from "@agentnexus/claw-runtime-ui";

type TicketsCopy = {
  title: string;
  desc: string;
  filter: string;
  columns: string[];
  rows: string[][];
};

export function AccessTicketsTable({ copy }: { copy: TicketsCopy }) {
  const [filtered, setFiltered] = useState(false);
  const rows = filtered ? copy.rows.filter((row) => row[5] === "review") : copy.rows;

  return (
    <section className="panel tickets">
      <div className="panel-header">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.desc}</p>
        </div>
        <Button className="ghost-button small" type="button" variant="ghost" onClick={() => setFiltered((current) => !current)}>
          <span className="icon icon-filter" aria-hidden="true" />
          {copy.filter}
        </Button>
      </div>
      <div className="ticket-table">
        <div className="table-head">
          {copy.columns.map((column) => (
            <span key={column}>{column}</span>
          ))}
        </div>
        {rows.map(([ticket, employee, intent, resource, decision, tone]) => (
          <div className="ticket-row" key={ticket}>
            <span className="ticket-id">{ticket}</span>
            <span>{employee}</span>
            <span>{intent}</span>
            <span>{resource}</span>
            <span className={`status-chip ${tone}`}>{decision}</span>
          </div>
        ))}
      </div>
    </section>
  );
}
