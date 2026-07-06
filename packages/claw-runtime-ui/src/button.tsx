import type { ButtonHTMLAttributes, PropsWithChildren } from "react";
import "./tokens.css";

type ButtonProps = PropsWithChildren<ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" }>;

export function Button({ children, className, variant = "primary", ...props }: ButtonProps) {
  const classes = ["an-button", `an-button-${variant}`, className].filter(Boolean).join(" ");

  return (
    <button className={classes} {...props}>
      {children}
    </button>
  );
}
