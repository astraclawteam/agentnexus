type ResourceMapCopy = {
  title: string;
  desc: string;
  tabs: string[];
  aria: string;
  nodes: Record<string, string[]>;
};

export function ResourceMap({ copy }: { copy: ResourceMapCopy }) {
  return (
    <section className="panel resource-panel" aria-label={copy.aria}>
      <div className="panel-header">
        <div>
          <h2>{copy.title}</h2>
          <p>{copy.desc}</p>
        </div>
        <div className="segmented" role="tablist" aria-label={copy.title}>
          {copy.tabs.map((tab, index) => (
            <button className={index === 0 ? "is-selected" : ""} key={tab} type="button">
              {tab}
            </button>
          ))}
        </div>
      </div>
      <div className="resource-map">
        <svg viewBox="0 0 760 360" role="img" aria-label={copy.aria}>
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#5e7a7d" />
            </marker>
          </defs>
          <g className="links">
            <path d="M150 180 C250 80 330 70 440 90" />
            <path d="M150 180 C260 145 330 145 440 145" />
            <path d="M150 180 C260 210 330 215 440 215" />
            <path d="M150 180 C250 285 340 300 455 278" />
            <path d="M575 145 C640 145 665 178 680 225" />
            <path d="M575 215 C638 216 662 195 680 155" />
          </g>
          <MapNode className="node-core" copy={copy.nodes.core} height={86} width={192} x={54} y={137} />
          <MapNode className="node-source" copy={copy.nodes.source} width={142} x={438} y={54} />
          <MapNode className="node-knowledge" copy={copy.nodes.knowledge} width={142} x={438} y={119} />
          <MapNode className="node-system" copy={copy.nodes.finance} width={142} x={438} y={189} />
          <MapNode className="node-system" copy={copy.nodes.mes} width={142} x={438} y={255} />
          <MapNode className="node-file" copy={copy.nodes.file} width={96} x={646} y={128} />
          <MapNode className="node-file" copy={copy.nodes.receipt} width={96} x={646} y={215} />
        </svg>
      </div>
    </section>
  );
}

function MapNode({
  className,
  copy,
  height = 56,
  width,
  x,
  y
}: {
  className: string;
  copy: string[];
  height?: number;
  width: number;
  x: number;
  y: number;
}) {
  return (
    <g className={`map-node ${className}`} transform={`translate(${x} ${y})`}>
      <rect width={width} height={height} />
      <text x="15" y="24">
        {copy[0]}
      </text>
      <text x="15" y={height > 60 ? "55" : "43"}>
        {copy[1]}
      </text>
    </g>
  );
}
