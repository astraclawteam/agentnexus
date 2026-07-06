import type { ButtonHTMLAttributes, PropsWithChildren } from "react";
import "./tokens.css";

type ButtonProps = PropsWithChildren<ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" }>;

export function Button({ children, variant = "primary", ...props }: ButtonProps) {
  return (
    <button className={`an-button an-button-${variant}`} {...props}>
      {children}
    </button>
  );
}
