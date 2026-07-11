import { useState } from "react";
import { AgentChatShell, type RuntimeMessage } from "@xiaozhiclaw/runtime-ui";

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
  const [messages, setMessages] = useState<RuntimeMessage[]>([]);
  const [draft, setDraft] = useState("");

  function send({ text }: { text: string }) {
    if (!text) {
      return;
    }
    setMessages((current) => [
      ...current,
      { id: `user-${current.length}`, role: "user", content: `${copy.sentPrefix}: ${text}` }
    ]);
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
          <div className="chat-content">
            <div className="quick-prompts">
              {copy.prompts.map((prompt) => (
                <button key={prompt} type="button" onClick={() => setDraft(prompt)}>
                  {prompt}
                </button>
              ))}
            </div>
            <AgentChatShell
              labels={{
                conversation: copy.title,
                promptInput: { send: copy.send },
                attachments: {
                  uploading: copy.desc,
                  uploadFailed: copy.desc,
                  remove: (name) => `${copy.close}: ${name}`
                },
                messageList: {
                  list: copy.title,
                  roles: { assistant: copy.title, system: copy.title, user: copy.sentPrefix }
                }
              }}
              messages={[{ id: "intro", role: "assistant", content: copy.intro }, ...messages]}
              value={draft}
              attachments={[]}
              placeholder={copy.input}
              onChange={setDraft}
              onSend={send}
            />
          </div>
        </section>
      </div>
    </>
  );
}
