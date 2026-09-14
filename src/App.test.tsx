import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

const health = {
  service: "soc-ai-agent-demo",
  status: "ok",
  mode: "live-deepseek",
  provider: "DeepSeek",
  model: "deepseek-flash",
  endpoint: "https://api.deepseek.com",
  healthDetail:
    "Authenticated catalog probe succeeded. Generation is verified when a run starts.",
  checkedAt: new Date().toISOString(),
  capabilities: { incident_generation: true },
  models: ["deepseek-flash"],
};

describe("App", () => {
  afterEach(cleanup);
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json(health)),
    );
  });

  it("guides a first run with honest provider and synthetic environment labels", async () => {
    render(<App />);
    expect(
      screen.getByRole("heading", { name: /sentinel.*soc/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /generate incident/i }),
    ).toBeEnabled();
    expect(await screen.findByText("DeepSeek reachable")).toBeInTheDocument();
    expect(
      screen.getByText(
        /tool responses, security events, tickets, and containment are synthetic/i,
      ),
    ).toBeVisible();
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(screen.getByText("Every signal has a story.")).toBeVisible();
  });

  it("navigates graph, evidence, and report while preserving first-run state", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("DeepSeek reachable");
    await user.click(screen.getByRole("tab", { name: "Execution graph" }));
    expect(screen.getByText("Live LangGraph Execution")).toBeVisible();
    expect(screen.getByText("Cyclic Handoff Trace")).toBeVisible();
    expect(screen.getByText("Every signal has a story.")).not.toBeVisible();
    await user.keyboard("{ArrowRight}");
    expect(
      screen.getByRole("tab", { name: "Evidence & replay" }),
    ).toHaveFocus();
    expect(screen.getByText("Snapshots & Alternate Analysis")).toBeVisible();
    expect(
      screen.getByRole("combobox", { name: "Filter API evidence" }),
    ).toBeVisible();
    await user.keyboard("{End}");
    expect(screen.getByText("Final Incident Report")).toBeVisible();
    expect(screen.getByRole("button", { name: "PDF" })).toBeDisabled();
    await user.keyboard("{Home}");
    expect(screen.getByText("Every signal has a story.")).toBeVisible();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("shows unavailable status when the health request fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("offline");
      }),
    );
    render(<App />);
    expect(await screen.findByText("Provider unavailable")).toBeVisible();
    expect(screen.queryByText("DeepSeek reachable")).not.toBeInTheDocument();
  });
});
