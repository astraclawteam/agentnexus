import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { AppShell } from "./app/AppShell";
import "./styles.css";

export function App() {
  return <AppShell />;
}

const root = document.getElementById("root");
if (root) {
  const appRoot = createRoot(root);
  flushSync(() => {
    appRoot.render(<App />);
  });
}
