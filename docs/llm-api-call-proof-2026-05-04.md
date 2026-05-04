# Live LLM API Call Proof

Generated: 2026-05-04T16:36:48.229Z

Base URL: https://security-ops-playbook-analyzer.netlify.app

Health:
- Status: ok
- Mode: live-glm
- Provider: z.ai
- Model: glm-5.1
- Tool model: glm-5-turbo
- Orchestration provider: z.ai

SSE event counts:
- agent-run: {"start":1,"timeline":5,"node_start":9,"api_call":1,"delta":9,"incident":1,"checkpoint":5,"node_complete":8,"tool_fanout_required":1,"approval_required":1,"done":1}
- resume-run: {"node_start":4,"timeline":2,"checkpoint":2,"node_complete":4,"api_call":1,"delta":1,"report":1,"complete":1,"done":1}
- replay-run: {"node_start":1,"api_call":1,"timeline":1,"checkpoint":1,"node_complete":1,"done":1}

Result: PASS. Every row below is a real LLM-backed API call with request messages, response evidence, and token usage greater than zero.

Total verified tokens: 11010

| Call path | Type | Provider | Model | Status | Tokens | Latency | Messages | Response evidence |
|---|---:|---|---|---|---:|---:|---|---|
| /api/agent-run supervisor | llm | z.ai | glm-5-turbo | 200 ok | 464 | 8112ms | yes | yes |
| /api/virustotal/lookup | llm | z.ai | glm-5-turbo | 200 ok | 814 | 4852ms | yes | yes |
| /api/abuseipdb/check | llm | z.ai | glm-5-turbo | 200 ok | 762 | 3810ms | yes | yes |
| /api/activedirectory/user | llm | z.ai | glm-5-turbo | 200 ok | 771 | 3471ms | yes | yes |
| /api/okta/user-risk | llm | z.ai | glm-5-turbo | 200 ok | 882 | 5200ms | yes | yes |
| /api/edr/endpoint | llm | z.ai | glm-5-turbo | 200 ok | 881 | 3951ms | yes | yes |
| /api/siem/search | llm | z.ai | glm-5-turbo | 200 ok | 876 | 5847ms | yes | yes |
| /api/m365/audit | llm | z.ai | glm-5-turbo | 200 ok | 806 | 4837ms | yes | yes |
| /api/cloudtrail/search | llm | z.ai | glm-5-turbo | 200 ok | 887 | 4842ms | yes | yes |
| /api/servicenow/ticket | llm | z.ai | glm-5-turbo | 200 ok | 864 | 4421ms | yes | yes |
| /api/jira/issue | llm | z.ai | glm-5-turbo | 200 ok | 735 | 2707ms | yes | yes |
| /api/resume-run report | llm | z.ai | glm-5.1 | 200 ok | 1718 | 17694ms | yes | yes |
| /api/replay-run | llm | z.ai | glm-5.1 | 200 ok | 550 | 9518ms | yes | yes |

Verification window:
- Started: 2026-05-04T16:35:26.564Z
- Finished: 2026-05-04T16:36:48.229Z
