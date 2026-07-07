import { FormEvent, useState } from "react";
import { Button, Input } from "@agentnexus/claw-runtime-ui";
import { defaultAgentAPI, type AgentTool, type StartAgentRunRequest, type StartAgentRunResponse, type AgentRunMessageResponse } from "./setup-api";

type AgentCopy = {
  open: string;
  title: string;
  desc: string;
  close: string;
  intro: string;
  prompts: string[];
  input: string;
  send: string;
  sentPrefix: string;
};

type GatewayAgentAPI = {
  startAgentRun(input: StartAgentRunRequest): Promise<StartAgentRunResponse>;
  sendAgentRunMessage(runID: string, input: { enterprise_id: string; message: string }): Promise<AgentRunMessageResponse>;
};

export function GatewayAgentLauncher({
  copy,
  enterpriseID = "ent_dev",
  actorUserID = "admin_dev",
  api = defaultAgentAPI
}: {
  copy: AgentCopy;
  enterpriseID?: string;
  actorUserID?: string;
  api?: GatewayAgentAPI;
}) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<string[]>([]);
  const [draft, setDraft] = useState("");
  const [runID, setRunID] = useState("");
  const [tools, setTools] = useState<AgentTool[]>([]);

  async function send(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const message = draft.trim();
    if (!message) {
      return;
    }
    setMessages((current) => [...current, `${copy.sentPrefix}: ${message}`]);
    setDraft("");
    if (!runID) {
      const requestID = `console-${Date.now()}`;
      const run = await api.startAgentRun({
        enterprise_id: enterpriseID,
        actor_user_id: actorUserID,
        request_id: requestID,
        trace_id: requestID,
        goal: message
      });
      setRunID(run.agent_run_id);
      setTools(run.tools ?? []);
      return;
    }
    await api.sendAgentRunMessage(runID, { enterprise_id: enterpriseID, message });
  }

  return (
    <>
      <button className="floating-agent" aria-label={copy.open} type="button" onClick={() => setOpen(true)}>
        <span className="icon icon-spark" aria-hidden="true" />
      </button>
      <div className={`agent-chat ${open ? "is-open" : ""}`} aria-hidden={!open}>
        <section className="agent-chat-panel" aria-label={copy.title}>
          <header className="agent-chat-head">
            <div>
              <h2>{copy.title}</h2>
              <p>{copy.desc}</p>
            </div>
            <button className="icon-button" aria-label={copy.close} title={copy.close} type="button" onClick={() => setOpen(false)}>
              <span className="icon icon-x" aria-hidden="true" />
            </button>
          </header>
          <div className="chat-messages">
            <div className="chat-bubble assistant">{copy.intro}</div>
            <div className="quick-prompts">
              {copy.prompts.map((prompt) => (
                <button key={prompt} type="button" onClick={() => setDraft(prompt)}>
                  {prompt}
                </button>
              ))}
            </div>
            {messages.map((message) => (
              <div className="chat-bubble user" key={message}>
                {message}
              </div>
            ))}
            {runID ? <div className="chat-bubble assistant">Agent run: {runID}</div> : null}
            {tools.length > 0 ? (
              <div className="agent-tools" aria-label="Agent tools">
                {tools.map((tool) => (
                  <span key={tool.name}>{tool.name}</span>
                ))}
              </div>
            ) : null}
          </div>
          <form className="chat-input" onSubmit={send}>
            <Input value={draft} onChange={(event) => setDraft(event.currentTarget.value)} placeholder={copy.input} />
            <Button className="primary-button" type="submit">
              {copy.send}
            </Button>
          </form>
        </section>
      </div>
    </>
  );
}
