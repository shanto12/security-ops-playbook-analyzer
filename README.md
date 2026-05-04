# SOC AI Agent Demo

Enterprise-grade single-page demo showing an AI-driven SOC incident investigation with visible LangGraph concepts: supervisor routing, specialist subgraphs, checkpointing, interrupt/resume, time travel, Send-style parallel supersteps, map-reduce evidence gathering, streaming, and an API transparency log.

Independent concept demo. Synthetic incident data only.

- Live app: https://security-ops-playbook-analyzer.netlify.app
- GitHub: https://github.com/shanto12/security-ops-playbook-analyzer

## Live Workflow

1. Click **Generate Incident**.
2. The hosted graph provider generates a unique incident and streams graph events over SSE.
3. The supervisor and triage agents route the run.
4. The hosted graph emits ten enterprise tool-call records in a Send-style superstep; each enterprise endpoint is also independently callable as a real GLM-backed HTTP route.
5. Containment pauses for analyst approval.
6. Approve, reject, or edit the action.
7. The resume function completes containment, ticketing, notification, and the final report.
8. Fork any checkpoint to demonstrate time-travel debugging.
9. Export the run as JSON or open a browser-native print/save-to-PDF report.

## Enterprise Tool Endpoints

Each endpoint is a real Netlify Function route that calls Z.ai to synthesize fresh structured JSON.

- `/api/virustotal/lookup`
- `/api/abuseipdb/check`
- `/api/activedirectory/user`
- `/api/servicenow/ticket`
- `/api/jira/issue`
- `/api/siem/search`
- `/api/shodan/host`
- `/api/firewall/block`
- `/api/edr/endpoint`
- `/api/slack/notify`
- `/api/whois/lookup`
- `/api/okta/user-risk`
- `/api/m365/audit`
- `/api/cloudtrail/search`

## Configuration

```bash
GLM_API_KEY=<z.ai key>
GLM_MODEL=glm-5.1
GLM_TOOL_MODEL=glm-5-turbo
GLM_BASE_URL=https://api.z.ai/api/coding/paas/v4
FIREWORKS_API_KEY=<optional fireworks key>
FIREWORKS_MODEL=accounts/fireworks/models/deepseek-v4-pro
FIREWORKS_BASE_URL=https://api.fireworks.ai/inference/v1
```

The browser never receives provider keys. Local development reads them from environment variables; production stores them as Netlify environment variables.

## Commands

```bash
npm install
npm run verify
npm run e2e
npm run build
```

For local function testing:

```bash
GLM_API_KEY="$(security find-generic-password -s codex-zai-api-key -w)" \
GLM_BASE_URL="https://api.z.ai/api/coding/paas/v4" \
GLM_MODEL="glm-5.1" \
npx netlify dev --offline --port 8888 --target-port 5176 --functions netlify/functions \
  --command "npm run dev -- --host 127.0.0.1 --port 5176"
```

## Verification

- `npm run verify`: lint, unit tests, TypeScript, production build.
- `npm run e2e`: desktop and mobile first-viewport Playwright smoke.
- `npm audit --omit=dev`: production dependency audit.
- Live provider smoke tested locally and in production through `/api/health`, `/api/jira/issue`, `/api/agent-run`, `/api/resume-run`, and `/api/replay-run`.
