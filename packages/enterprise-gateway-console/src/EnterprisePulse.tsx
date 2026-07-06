type PulseCopy = {
  enterprise: string;
  privateEnv: string;
  pulse: {
    brandSub: string;
    currentEnterprise: string;
    orgSnapshot: string;
    todayPulse: string;
    pendingSignals: string;
    recentEvents: string;
    statusOnline: string;
    policyPending: string;
    orgVersion: string;
    stats: string[][];
    pulseStats: string[][];
    signals: string[][];
    events: string[];
  };
};

export function EnterprisePulse({ copy }: { copy: PulseCopy }) {
  return (
    <aside className="pulse" aria-label="Enterprise pulse">
      <div className="brand">
        <div className="brand-mark" aria-hidden="true" />
        <div>
          <div className="brand-name">企业网关</div>
          <div className="brand-sub">{copy.pulse.brandSub}</div>
        </div>
      </div>

      <section className="sidebar-identity">
        <div className="identity-label">{copy.pulse.currentEnterprise}</div>
        <div className="identity-name">{copy.enterprise}</div>
        <div className="identity-meta">{copy.privateEnv}</div>
      </section>

      <section className="side-section">
        <div className="side-section-title">{copy.pulse.orgSnapshot}</div>
        {copy.pulse.stats.map(([label, value]) => (
          <div className="side-stat" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </section>

      <section className="side-section">
        <div className="side-section-title">{copy.pulse.todayPulse}</div>
        <div className="pulse-grid">
          {copy.pulse.pulseStats.map(([value, label]) => (
            <div key={label}>
              <strong>{value}</strong>
              <span>{label}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="side-section">
        <div className="side-section-title">{copy.pulse.pendingSignals}</div>
        <div className="signal-list">
          {copy.pulse.signals.map(([id, label, value, tone]) => (
            <div className="signal-row" key={id}>
              <span className={`signal-dot ${tone}`} />
              <span>{label}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="side-section side-events">
        <div className="side-section-title">{copy.pulse.recentEvents}</div>
        {copy.pulse.events.map((event) => (
          <div className="event-item" key={event}>
            <span />
            <p>{event}</p>
          </div>
        ))}
      </section>

      <section className="sidebar-status">
        <div className="status-row">
          <span className="dot dot-ok" />
          <span>{copy.pulse.statusOnline}</span>
        </div>
        <div className="status-row">
          <span className="dot dot-warn" />
          <span>{copy.pulse.policyPending}</span>
        </div>
        <div className="status-row muted">
          <span>{copy.pulse.orgVersion}</span>
        </div>
      </section>
    </aside>
  );
}
