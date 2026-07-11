import { useState } from "react";
import {
  AgentChatShell,
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetTitle,
  SheetTrigger,
  type RuntimeMessage
} from "@xiaozhiclaw/runtime-ui";

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
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <button className="agent-launcher" aria-label={copy.open} type="button">
          <span className="icon icon-spark" aria-hidden="true" />
        </button>
      </SheetTrigger>
      <SheetContent side="right" className="agent-chat-panel" aria-modal="true">
        <header className="agent-chat-head">
          <div>
            <SheetTitle>{copy.title}</SheetTitle>
            <SheetDescription>{copy.desc}</SheetDescription>
          </div>
          <SheetClose asChild>
            <button className="icon-button" aria-label={copy.close} title={copy.close} type="button">
              <span className="icon icon-x" aria-hidden="true" />
            </button>
          </SheetClose>
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
      </SheetContent>
    </Sheet>
  );
}
