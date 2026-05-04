# Live LLM API Call Proof

Generated: 2026-05-04T17:24:50.945Z

Base URL: https://security-ops-playbook-analyzer.netlify.app

Health:
- Status: ok
- Mode: live-glm
- Provider: z.ai
- Model: glm-5.1
- Tool model: glm-5-turbo
- Orchestration provider: z.ai

SSE event counts:
- agent-run: {"start":1,"timeline":18,"node_start":14,"api_call":13,"delta":8,"incident":1,"checkpoint":27,"node_complete":14,"agent_route":12,"tool_fanout_required":1,"approval_required":1,"done":1}
- resume-run: {"node_start":4,"timeline":2,"checkpoint":2,"node_complete":4,"api_call":1,"delta":1,"report":1,"complete":1,"done":1}
- replay-run: {"node_start":1,"api_call":1,"timeline":1,"checkpoint":1,"node_complete":1,"done":1}

Result: PASS. Every row below is a real LLM-backed API call with request messages, response evidence, and token usage greater than zero.

Total verified tokens: 12829

| Call path | Type | Provider | Model | Status | Tokens | Latency | Messages | Response evidence |
|---|---:|---|---|---|---:|---:|---|---|
| /api/agent-run supervisor | llm | z.ai | glm-5-turbo | 200 ok | 586 | 9540ms | yes | yes |
| /api/virustotal/lookup | llm | z.ai | glm-5-turbo | 200 ok | 927 | 5402ms | yes | yes |
| /api/abuseipdb/check | llm | z.ai | glm-5-turbo | 200 ok | 870 | 4948ms | yes | yes |
| /api/activedirectory/user | llm | z.ai | glm-5-turbo | 200 ok | 845 | 3278ms | yes | yes |
| /api/okta/user-risk | llm | z.ai | glm-5-turbo | 200 ok | 972 | 7329ms | yes | yes |
| /api/edr/endpoint | llm | z.ai | glm-5-turbo | 200 ok | 983 | 5628ms | yes | yes |
| /api/siem/search | llm | z.ai | glm-5-turbo | 200 ok | 958 | 5476ms | yes | yes |
| /api/m365/audit | llm | z.ai | glm-5-turbo | 200 ok | 931 | 5840ms | yes | yes |
| /api/cloudtrail/search | llm | z.ai | glm-5-turbo | 200 ok | 918 | 6370ms | yes | yes |
| /api/servicenow/ticket | llm | z.ai | glm-5-turbo | 200 ok | 988 | 6415ms | yes | yes |
| /api/jira/issue | llm | z.ai | glm-5-turbo | 200 ok | 825 | 2368ms | yes | yes |
| /api/resume-run report | llm | z.ai | glm-5.1 | 200 ok | 2469 | 21296ms | yes | yes |
| /api/replay-run | llm | z.ai | glm-5.1 | 200 ok | 557 | 12813ms | yes | yes |

Verification window:
- Started: 2026-05-04T17:23:10.719Z
- Finished: 2026-05-04T17:24:50.945Z
