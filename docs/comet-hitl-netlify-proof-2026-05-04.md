# Comet Browser HITL and Netlify Proof

Generated: 2026-05-04 17:20 America/Chicago

Live URL: https://security-ops-playbook-analyzer.netlify.app/?proof=postfix-20260504

Result: PASS for the deployed app in Comet. Comet Assistant was explicitly asked to test the app end-to-end, but it reported that it could not perform click-by-click browser control in this session. I then used Comet itself to run the deployed Netlify app end-to-end and captured the evidence below.

## Comet Assistant Attempt

Comet Assistant prompt:

> Please understand the whole SOC AI Agent Demo web application on this live Netlify page and test it end-to-end using browser control. Open additional tabs if useful. Specifically verify: generate incident; real LLM/API log rows with nonzero tokens; cyclic LangGraph handoffs and back edges; checkpoints/time travel; HITL approval card behavior; Approve disabled until all 10 enterprise tool calls complete; click Approve after 10/10; final report renders with every section populated and no 'No report entries captured'; JSON/PDF export buttons; replay/fork; and no failed API rows or UI errors.

Assistant result:

- It opened/read the live page but said it could not perform actual click-by-click browser interaction.
- A follow-up asked it to use Comet browser agent / browser control mode and request permission if needed.
- It again said it could only read the HTML/DOM snapshot and could not drive the page.

Screenshots:

- `docs/evidence/comet-hitl-02-assistant-browser-control-prompt.png`
- `docs/evidence/comet-hitl-03-assistant-controlling-approval-ready.png`
- `docs/evidence/comet-hitl-04-assistant-clicked-approve-final-report.png`

## Direct Comet Browser Run

Run identity:

- Incident ID: `INC-1777932611`
- Thread ID: `thread-a5f9fe8c-aac`
- Run ID: `run-4950b44f`

Verified in Comet:

- Generate Incident started a live Netlify run.
- API Transparency Log showed 10 enterprise tool rows with nonzero LLM token counts.
- HITL approval card appeared during containment.
- At 5/10 tool calls, the card showed `Waiting for LLM-backed tool evidence: 5/10 complete`.
- At 10/10 tool calls, the card changed to `All enterprise tool evidence is captured` and Approve was enabled.
- Clicking Approve logged `Command(resume=...) received` and resumed the graph.
- Reporting Agent produced the final incident report.
- Final report sections were populated and no `No report entries captured` placeholder was visible.
- JSON export downloaded successfully as `soc-run-export.json`.
- PDF export opened a printable incident report tab.
- Forking a checkpoint added a time-travel checkpoint and a `GLM-5.1 Time Travel Debugger` API row.

Observed metrics after completion:

- Checkpoints: 30
- Tool calls: 10/10
- Tokens after final report: 16,977
- Tokens after time-travel fork: 17,919
- MTTR: 17.5s

Downloaded JSON export checks:

- Evidence file: `docs/evidence/comet-post-fix-soc-run-export.json`
- API log rows: 25
- MITRE Mapping items: 2
- Investigation Timeline items: 5
- Agent Routing & Cycles items: 12
- Containment Actions items: 3
- Recommendations items: 4
- Analyst Decisions items: 1

Screenshots:

- `docs/evidence/comet-post-fix-01-running.png`
- `docs/evidence/comet-post-fix-02-hitl-waiting-5-of-10.png`
- `docs/evidence/comet-post-fix-03-hitl-ready-10-of-10.png`
- `docs/evidence/comet-post-fix-04-approve-clicked-resuming.png`
- `docs/evidence/comet-post-fix-05-final-report-populated.png`
- `docs/evidence/comet-post-fix-06-pdf-export-view.png`
- `docs/evidence/comet-post-fix-07-time-travel-fork.png`

Related automated Netlify proof:

- `docs/final-report-proof-2026-05-04-post-fix.md`
