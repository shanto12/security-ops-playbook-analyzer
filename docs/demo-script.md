# Demo Script

## 90 Seconds

This is a SOC AI Agent demo focused on LangGraph mechanics. I click Generate Incident once. GLM creates a fresh incident, the supervisor routes the graph, and ten enterprise tools are called through real HTTP endpoints. The graph pauses before containment, which demonstrates interrupt/resume. After approval, the system creates ticketing and notification artifacts and streams a final incident report. I can also fork any checkpoint to show time-travel debugging.

## 5 Minutes

1. Open the Demo Guide and health panel.
2. Generate a live incident.
3. Point out the graph node state changes and checkpoints.
4. Open the API log and show LLM/tool payloads.
5. Approve or edit containment.
6. Show final report export.
7. Fork a checkpoint and explain replay/fork behavior.

## 15 Minutes

Cover the Netlify Function boundaries, SSE parser, tool gateway, prompt contracts, JSON mode, model routing, CSP, tests, threat model, and known limits.
