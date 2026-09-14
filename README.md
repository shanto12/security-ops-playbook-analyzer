# Sentinel — SOC investigation workspace

A public portfolio lab that turns a synthetic security alert into a transparent investigation, an analyst decision, and a downloadable report. The UI separates the case overview, execution graph, evidence/replay, and report so the analyst can follow one stage at a time.

- [Live application](https://security-ops-playbook-analyzer.netlify.app)
- [Source](https://github.com/shanto12/security-ops-playbook-analyzer)

## What actually runs

The initial investigation executes a real `@langchain/langgraph` StateGraph with cyclic edges. DeepSeek Flash generates the incident, ten synthetic tool responses, the final report, and alternate checkpoint analysis. Model requests and responses are recorded with actual provider, model, latency, usage, and status. Z.ai remains an optional configured provider.

The enterprise system names are **simulated interfaces**. There are no connections to a real SIEM, EDR, directory, ticketing system, firewall, or Slack account. Approval records a demo decision; containment, ticketing, and notifications are synthesized locally. Specialist routes use a predefined cyclic plan unless the model supplies a routing plan.

Checkpoints live in the browser session, not a durable shared database. Resume is a separate stateless function using the submitted checkpoint context; replay asks the model for an alternate branch analysis. They are not a persistent LangGraph checkpointer/Command replay service. Reloading clears the current investigation.

## Try the workflow

1. Choose **Generate Incident** or **Start first investigation**.
2. Follow the execution stages and ten synthetic evidence requests.
3. Inspect graph nodes, handoffs, checkpoint state, and API audit details.
4. Approve, reject, or edit the simulated containment request.
5. Read the final report, export the evidence as JSON, or open the print/save-PDF view.
6. Select a checkpoint and fork an alternate branch analysis.

## Configuration

See `.env.example`. Production credentials belong in Netlify environment variables. The browser never receives them. `AI_PROVIDER=deepseek` selects `deepseek-flash`; `AI_PROVIDER=glm` preserves the optional GLM configuration. Thinking is disabled and completion output is bounded. Failed tool requests are not automatically retried.

`GET /api/health` makes an authenticated model-catalog probe. It reports model reachability, explicitly **not** generation quota or an end-to-end successful run. Provider failures are surfaced in the workflow. Report-model failure does not emit a successful completion.

## Development and verification

```sh
npm ci
npm run verify
npm audit --omit=dev
npm run build
```

Use `netlify dev` with credentials supplied securely to the local runtime to exercise Functions. For deployment, use the Netlify connector first. Generated `netlify/functions/*.mjs` bundles include the shared provider configuration; source lives in `netlify/functions-src/` and `netlify/lib/`.

```sh
node scripts/verify-refresh.mjs        # Read-only production UI/header checks
node scripts/verify-refresh.mjs --live # Bounded paid production verification
```

The live suite caps generation POSTs, records real provider evidence, and reuses the first run's captured input for alternate decision paths. Historical May 2026 evidence in `docs/` describes the prior release and is not current proof.

## Operational boundaries

This is an unauthenticated public demonstration, not an enterprise security deployment. No login/password-manager workflow is applicable. Browser-session state is not durable or access controlled. The existing per-instance run limiter is best effort and is not a global spending cap. Set provider/account spending limits or add durable rate limiting before broader traffic. No top-ups are performed by the app.
