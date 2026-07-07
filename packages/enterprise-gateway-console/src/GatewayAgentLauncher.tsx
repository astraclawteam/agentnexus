import { FormEvent, useState } from "react";
import { Button, Input } from "@agentnexus/claw-runtime-ui";

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

export function GatewayAgentLauncher({ copy }: { copy: AgentCopy }) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<string[]>([]);
  const [draft, setDraft] = useState("");

  function send(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft.trim()) {
      return;
    }
    setMessages((current) => [...current, `${copy.sentPrefix}: ${draft.trim()}`]);
    setDraft("");
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
