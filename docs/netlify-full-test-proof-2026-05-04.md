# Final Report Production Proof

Generated: 2026-05-04T16:38:44.483Z

Base URL: https://security-ops-playbook-analyzer.netlify.app

Result: PASS. The deployed app completed incident generation, ten LLM-backed enterprise tool calls, gated human approval, final report generation, JSON export, and time-travel replay.

Evidence:
- Approval disabled before tool evidence completed: yes
- Tool rows with nonzero tokens: 10
- Reporting Agent LLM rows visible: 2
- Failed API Transparency Log rows: 0
- JSON export filename: soc-run-export.json

Screenshot artifacts:
- Initial live app: docs/evidence/netlify-full-test-01-initial.png
- Approval card waiting for tool evidence: docs/evidence/netlify-full-test-02-approval-waiting-tools.png
- Ten LLM-backed tool rows visible: docs/evidence/netlify-full-test-03-tool-llm-evidence.png
- Final report rendered: docs/evidence/netlify-full-test-04-final-report.png
- Replay proof after checkpoint fork: docs/evidence/netlify-full-test-05-replay-proof.png

Final report sections verified:
- Executive Summary
- Root Cause
- MITRE Mapping
- Investigation Timeline
- Containment Actions
- Recommendations
- Analyst Decisions
- Tool Result Summary

Visible tool rows:

| Tool row | Tokens |
|---|---:|
| 11:37:15 AMVirusTotalEnrichment Agent5010ms844 tok | 844 |
| 11:37:21 AMAbuseIPDBEnrichment Agent5027ms791 tok | 791 |
| 11:37:26 AMActive DirectoryIdentity Investigation Agent4933ms796 tok | 796 |
| 11:37:34 AMOktaIdentity Investigation Agent6832ms903 tok | 903 |
| 11:37:40 AMEDREndpoint Investigation Agent5266ms904 tok | 904 |
| 11:37:47 AMSIEMLog Analysis Agent6306ms896 tok | 896 |
| 11:37:54 AMMicrosoft 365 AuditLog Analysis Agent6619ms910 tok | 910 |
| 11:38:03 AMAWS CloudTrailLog Analysis Agent7516ms904 tok | 904 |
| 11:38:12 AMServiceNowTicketing Agent8537ms895 tok | 895 |
| 11:38:16 AMJiraTicketing Agent2831ms745 tok | 745 |

Reporting rows:
- 11:37:10 AMGLM-5.1Supervisor Graph Orchestrator12470ms499 tok
- 11:38:33 AMGLM-5.1Reporting Agent16043ms4050 tok

Verification window:
- Started: 2026-05-04T16:36:56.358Z
- Finished: 2026-05-04T16:38:44.483Z
