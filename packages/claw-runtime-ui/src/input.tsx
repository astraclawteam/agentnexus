import type { InputHTMLAttributes } from "react";
import "./tokens.css";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  const classes = ["an-input", className].filter(Boolean).join(" ");

  return <input className={classes} {...props} />;
}
