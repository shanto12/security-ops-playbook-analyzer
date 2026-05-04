# Live LLM API Call Proof

Generated: 2026-05-04T14:44:54.832Z

Base URL: https://security-ops-playbook-analyzer.netlify.app

Health:
- Status: ok
- Mode: live-glm
- Provider: z.ai + fireworks
- Model: glm-5.1
- Tool model: glm-5-turbo
- Fireworks model: accounts/fireworks/models/deepseek-v4-pro

SSE event counts:
- agent-run: {"start":1,"timeline":5,"node_start":9,"api_call":1,"delta":11,"incident":1,"checkpoint":5,"node_complete":8,"tool_fanout_required":1,"approval_required":1,"done":1}
- resume-run: {"node_start":4,"timeline":2,"checkpoint":2,"node_complete":4,"api_call":1,"delta":1,"report":1,"complete":1,"done":1}
- replay-run: {"node_start":1,"api_call":1,"timeline":1,"checkpoint":1,"node_complete":1,"done":1}

Result: PASS. Every row below is a real LLM-backed API call with request messages, response evidence, and token usage greater than zero.

Total verified tokens: 11333

| Call path | Type | Provider | Model | Status | Tokens | Latency | Messages | Response evidence |
|---|---:|---|---|---|---:|---:|---|---|
| /api/agent-run supervisor | llm | fireworks | accounts/fireworks/models/deepseek-v4-pro | 200 ok | 457 | 10945ms | yes | yes |
| /api/virustotal/lookup | llm | z.ai | glm-5-turbo | 200 ok | 836 | 5217ms | yes | yes |
| /api/abuseipdb/check | llm | z.ai | glm-5-turbo | 200 ok | 822 | 4251ms | yes | yes |
| /api/activedirectory/user | llm | z.ai | glm-5-turbo | 200 ok | 775 | 3024ms | yes | yes |
| /api/okta/user-risk | llm | z.ai | glm-5-turbo | 200 ok | 916 | 5151ms | yes | yes |
| /api/edr/endpoint | llm | z.ai | glm-5-turbo | 200 ok | 916 | 7852ms | yes | yes |
| /api/siem/search | llm | z.ai | glm-5-turbo | 200 ok | 910 | 6848ms | yes | yes |
| /api/m365/audit | llm | z.ai | glm-5-turbo | 200 ok | 924 | 6628ms | yes | yes |
| /api/cloudtrail/search | llm | z.ai | glm-5-turbo | 200 ok | 917 | 6024ms | yes | yes |
| /api/servicenow/ticket | llm | z.ai | glm-5-turbo | 200 ok | 921 | 5460ms | yes | yes |
| /api/jira/issue | llm | z.ai | glm-5-turbo | 200 ok | 759 | 4893ms | yes | yes |
| /api/resume-run report | llm | z.ai | glm-5.1 | 200 ok | 1649 | 18059ms | yes | yes |
| /api/replay-run | llm | z.ai | glm-5.1 | 200 ok | 531 | 8085ms | yes | yes |

Verification window:
- Started: 2026-05-04T14:43:17.758Z
- Finished: 2026-05-04T14:44:54.832Z

Production UI browser check:
- Result: PASS. Playwright clicked Generate Incident on the live Netlify app and waited for the visible API Transparency Log to contain ten tool rows with token counts greater than zero.
- Netlify deploy ID: 69f8b06279682946396dc60a
- Screenshot artifact: docs/evidence/production-llm-tool-log.png

Visible tool rows captured from the production UI:

| Tool | Agent | Tokens | Latency |
|---|---|---:|---:|
| VirusTotal | Enrichment Agent | 846 | 4966ms |
| AbuseIPDB | Enrichment Agent | 770 | 3469ms |
| Active Directory | Identity Investigation Agent | 755 | 3966ms |
| Okta | Identity Investigation Agent | 862 | 5864ms |
| EDR | Endpoint Investigation Agent | 888 | 4791ms |
| SIEM | Log Analysis Agent | 882 | 7340ms |
| Microsoft 365 Audit | Log Analysis Agent | 893 | 5973ms |
| AWS CloudTrail | Log Analysis Agent | 887 | 5378ms |
| ServiceNow | Ticketing Agent | 880 | 5647ms |
| Jira | Ticketing Agent | 733 | 4207ms |
