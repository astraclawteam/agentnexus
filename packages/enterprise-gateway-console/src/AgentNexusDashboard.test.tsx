import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AgentNexusDashboard } from "./AgentNexusDashboard";

describe("AgentNexusDashboard", () => {
  it("renders operational console regions", () => {
    render(<AgentNexusDashboard />);

    expect(screen.getByRole("heading", { name: "AgentNexus" })).toBeInTheDocument();
    expect(screen.getByText("Enterprise Pulse")).toBeInTheDocument();
    expect(screen.getByText("Resource Map")).toBeInTheDocument();
    expect(screen.getByText("Access Tickets")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Connector Health" })).toBeInTheDocument();
    expect(screen.getByLabelText("Gateway Agent launcher")).toBeInTheDocument();
  });
});
