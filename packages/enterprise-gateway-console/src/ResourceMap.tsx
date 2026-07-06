const nodes = ["Legal", "Finance", "Knowledge", "File Store", "CRM"];

export function ResourceMap() {
  return (
    <section className="panel resource-map" aria-label="Resource map">
      <div className="panel-head">
        <h2>Resource Map</h2>
        <span>OpenFGA visible</span>
      </div>
      <div className="map-canvas">
        {nodes.map((node, index) => (
          <div className={`map-node node-${index}`} key={node}>
            {node}
          </div>
        ))}
        <div className="edge edge-a" />
        <div className="edge edge-b" />
        <div className="edge edge-c" />
      </div>
    </section>
  );
}
