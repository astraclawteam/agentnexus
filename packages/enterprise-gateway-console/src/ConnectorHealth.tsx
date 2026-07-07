import { Button } from "@agentnexus/claw-runtime-ui";

type ConnectorCopy = {
  title: string;
  desc: string;
  smoke: string;
  rows: string[][];
};

export function ConnectorHealth({ copy, onSmoke, smokeStatus }: { copy: ConnectorCopy; onSmoke?: () => void; smokeStatus?: string }) {
  return (
    <section className="panel health">
      <div className="panel-header">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.desc}</p>
        </div>
        <Button className="ghost-button small" type="button" variant="ghost" onClick={onSmoke}>
          <span className="icon icon-play" aria-hidden="true" />
          {copy.smoke}
        </Button>
      </div>
      {smokeStatus ? <p className="panel-status">{smokeStatus}</p> : null}
      <div className="connector-list">
        {copy.rows.map(([title, subtitle, status, tone], index) => (
          <div className="connector-item" key={title}>
            <span className={`connector-mark connector-${index}`} aria-hidden="true" />
            <div>
              <div className="connector-title">{title}</div>
              <div className="connector-sub">{subtitle}</div>
            </div>
            <strong className={`health-state ${tone}`}>{status}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}
