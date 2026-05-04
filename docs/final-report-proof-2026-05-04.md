# Final Report Production Proof

Generated: 2026-05-04T15:10:40.198Z

Base URL: https://security-ops-playbook-analyzer.netlify.app

Result: PASS. The deployed app completed incident generation, ten LLM-backed enterprise tool calls, gated human approval, final report generation, JSON export, and time-travel replay.

Evidence:
- Approval disabled before tool evidence completed: yes
- Tool rows with nonzero tokens: 10
- Reporting Agent LLM rows visible: 1
- JSON export filename: soc-run-export.json
- Screenshot artifact: docs/evidence/production-final-report-flow.png

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
| 10:08:38 AMVirusTotalEnrichment Agent7820ms832 tok | 832 |
| 10:08:56 AMAbuseIPDBEnrichment Agent17010ms844 tok | 844 |
| 10:09:04 AMActive DirectoryIdentity Investigation Agent6906ms780 tok | 780 |
| 10:09:11 AMOktaIdentity Investigation Agent6042ms849 tok | 849 |
| 10:09:19 AMEDREndpoint Investigation Agent6986ms903 tok | 903 |
| 10:09:32 AMSIEMLog Analysis Agent12180ms897 tok | 897 |
| 10:09:41 AMMicrosoft 365 AuditLog Analysis Agent8979ms909 tok | 909 |
| 10:09:50 AMAWS CloudTrailLog Analysis Agent7663ms903 tok | 903 |
| 10:09:59 AMServiceNowTicketing Agent8761ms908 tok | 908 |
| 10:10:05 AMJiraTicketing Agent4155ms752 tok | 752 |

Reporting rows:
- 10:10:29 AMGLM-5.1Reporting Agent22991ms3993 tok

Verification window:
- Started: 2026-05-04T15:08:22.340Z
- Finished: 2026-05-04T15:10:40.198Z
