# Live LLM API Call Proof

Generated: 2026-05-04T15:04:37.284Z

Base URL: https://security-ops-playbook-analyzer.netlify.app

Health:
- Status: ok
- Mode: live-glm
- Provider: z.ai + fireworks
- Model: glm-5.1
- Tool model: glm-5-turbo
- Fireworks model: accounts/fireworks/models/deepseek-v4-pro

SSE event counts:
- agent-run: {"start":1,"timeline":6,"node_start":9,"api_call":2,"delta":9,"incident":1,"checkpoint":5,"node_complete":8,"tool_fanout_required":1,"approval_required":1,"done":1}
- resume-run: {"node_start":4,"timeline":2,"checkpoint":2,"node_complete":4,"api_call":1,"delta":1,"report":1,"complete":1,"done":1}
- replay-run: {"node_start":1,"api_call":1,"timeline":1,"checkpoint":1,"node_complete":1,"done":1}

Result: PASS. Every row below is a real LLM-backed API call with request messages, response evidence, and token usage greater than zero.

Total verified tokens: 12073

| Call path | Type | Provider | Model | Status | Tokens | Latency | Messages | Response evidence |
|---|---:|---|---|---|---:|---:|---|---|
| /api/agent-run supervisor | llm | z.ai | glm-5-turbo | 200 ok | 487 | 9001ms | yes | yes |
| /api/virustotal/lookup | llm | z.ai | glm-5-turbo | 200 ok | 965 | 8663ms | yes | yes |
| /api/abuseipdb/check | llm | z.ai | glm-5-turbo | 200 ok | 878 | 5597ms | yes | yes |
| /api/activedirectory/user | llm | z.ai | glm-5-turbo | 200 ok | 823 | 4649ms | yes | yes |
| /api/okta/user-risk | llm | z.ai | glm-5-turbo | 200 ok | 945 | 7960ms | yes | yes |
| /api/edr/endpoint | llm | z.ai | glm-5-turbo | 200 ok | 965 | 6593ms | yes | yes |
| /api/siem/search | llm | z.ai | glm-5-turbo | 200 ok | 961 | 6938ms | yes | yes |
| /api/m365/audit | llm | z.ai | glm-5-turbo | 200 ok | 974 | 10362ms | yes | yes |
| /api/cloudtrail/search | llm | z.ai | glm-5-turbo | 200 ok | 968 | 13852ms | yes | yes |
| /api/servicenow/ticket | llm | z.ai | glm-5-turbo | 200 ok | 934 | 27093ms | yes | yes |
| /api/jira/issue | llm | z.ai | glm-5-turbo | 200 ok | 831 | 6014ms | yes | yes |
| /api/resume-run report | llm | z.ai | glm-5.1 | 200 ok | 1821 | 23984ms | yes | yes |
| /api/replay-run | llm | z.ai | glm-5.1 | 200 ok | 521 | 9039ms | yes | yes |

Verification window:
- Started: 2026-05-04T15:02:03.030Z
- Finished: 2026-05-04T15:04:37.284Z
