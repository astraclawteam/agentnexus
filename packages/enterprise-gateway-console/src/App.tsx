import { createRoot } from "react-dom/client";
import { DesignProvider } from "@xiaozhiclaw/runtime-ui";
import "@xiaozhiclaw/runtime-ui/styles.css";
import { AgentNexusDashboard } from "./AgentNexusDashboard";
import "./styles.css";

export function App() {
  return (
    <DesignProvider theme="light" accent="clay">
      <AgentNexusDashboard />
    </DesignProvider>
  );
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<App />);
}
