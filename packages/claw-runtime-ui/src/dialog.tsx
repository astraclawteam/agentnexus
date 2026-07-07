import type { PropsWithChildren } from "react";
import "./tokens.css";

export function Dialog({ children }: PropsWithChildren) {
  return <section className="an-dialog">{children}</section>;
}
