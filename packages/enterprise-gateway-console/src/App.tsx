import { createRoot } from "react-dom/client";
import { AgentNexusDashboard } from "./AgentNexusDashboard";
import "./styles.css";

export function App() {
  return <AgentNexusDashboard />;
}

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(<App />);
}
