import { Button } from "@agentnexus/claw-runtime-ui";

export function GatewayAgentLauncher() {
  return (
    <section className="panel launcher" aria-label="Gateway Agent launcher">
      <div className="panel-head">
        <h2>Gateway Agent</h2>
        <span>ready</span>
      </div>
      <div className="command-box">
        <span>Import organization from approved source</span>
        <Button variant="ghost">Preview</Button>
      </div>
      <div className="command-box">
        <span>Request access with policy guardrails</span>
        <Button variant="ghost">Run</Button>
      </div>
    </section>
  );
}
