# Architecture

## Runtime Shape

The public demo is optimized for Netlify:

- React + Vite single-page UI.
- Netlify Functions for `/api/health`, `/api/agent-run`, `/api/resume-run`, `/api/replay-run`, and the enterprise tool gateway.
- Server-Sent Events for long-running graph execution.
- Z.ai GLM-5.1 for incident generation, containment reasoning, reporting, and fallback orchestration.
- Z.ai GLM-5-Turbo for corporate tool endpoints because it is optimized for tool-heavy agent workflows and keeps the hosted demo under Netlify function limits.
- Fireworks `deepseek-v4-pro` for the hosted pre-approval graph superstep when configured, because it keeps the live approval path comfortably under Netlify's timeout.

## LangGraph Concepts Shown

- **StateGraph:** visual graph canvas and typed run state.
- **Supervisor:** routes the incident after GLM-5.1 assessment.
- **Subgraphs:** triage, enrichment, identity, endpoint, logs, containment, ticketing, notification, reporting.
- **Checkpointing:** every stage emits checkpoint IDs and state snapshots.
- **Interrupt/Resume:** containment emits a human approval card and resumes through `/api/resume-run`.
- **Parallel Send:** enterprise tools run in parallel waves.
- **Map-Reduce:** evidence tool results are reduced into containment and reporting decisions.
- **Time Travel:** `/api/replay-run` forks from a selected checkpoint.
- **Streaming:** GLM deltas and graph events stream over SSE.
- **Transparency:** every LLM/tool/human call appears in the API log.

## Hosted Execution Note

The production Netlify SSE path uses Fireworks `deepseek-v4-pro` when configured, with GLM-5-Turbo as fallback, for the first ten enterprise tool results so the approval interrupt is reached reliably inside Netlify's synchronous function window. The completed provider JSON is replayed into the SSE stream as small chunks for visible streaming, and the individual tool endpoints remain independently callable GLM-backed HTTP routes for live endpoint demonstrations.

## Netlify vs FastAPI Note

The original requirement mentioned ten FastAPI servers. Netlify Functions do not host long-running Python FastAPI processes, so the deployed implementation uses Netlify-native HTTP endpoints for the best interview experience. The UI and API surface still demonstrate the enterprise investigation pattern with real HTTP endpoints and live GLM-generated responses.
