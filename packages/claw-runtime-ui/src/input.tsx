import type { InputHTMLAttributes } from "react";
import "./tokens.css";

export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input className="an-input" {...props} />;
}
