# Final Report Production Proof

Generated: 2026-05-04T22:03:21.821Z

Base URL: https://security-ops-playbook-analyzer.netlify.app

Result: PASS. The deployed app completed incident generation, ten LLM-backed enterprise tool calls, gated human approval, final report generation, JSON export, and time-travel replay.

Evidence:
- Approval disabled before tool evidence completed: yes
- Cyclic handoff rows visible: 12
- Cyclic backtrack rows visible: 2
- Routing API rows visible: 12
- Tool rows with nonzero tokens: 10
- Reporting Agent LLM rows visible: 2
- Failed API Transparency Log rows: 0
- JSON export filename: soc-run-export.json

Screenshot artifacts:
- Initial live app: docs/evidence/production-post-fix-final-report-01-initial.png
- Approval card waiting for tool evidence: docs/evidence/production-post-fix-final-report-02-approval-waiting-tools.png
- Ten LLM-backed tool rows visible: docs/evidence/production-post-fix-final-report-03-tool-llm-evidence.png
- Cyclic graph state: docs/evidence/production-post-fix-final-report-03a-cyclic-graph.png
- Cyclic handoff trace: docs/evidence/production-post-fix-final-report-03b-cyclic-handoff-trace.png
- Handoff checkpoint state: docs/evidence/production-post-fix-final-report-03c-handoff-checkpoint-state.png
- Routing API evidence: docs/evidence/production-post-fix-final-report-03d-routing-api-evidence.png
- Final report rendered: docs/evidence/production-post-fix-final-report-04-final-report.png
- Replay proof after checkpoint fork: docs/evidence/production-post-fix-final-report-05-replay-proof.png

Final report sections verified:
- Executive Summary
- Root Cause
- MITRE Mapping
- Investigation Timeline
- Agent Routing & Cycles
- Containment Actions
- Recommendations
- Analyst Decisions
- Tool Result Summary

Final report section item counts:
- Executive Summary: text item(s)
- Root Cause: text item(s)
- MITRE Mapping: 3 item(s)
- Investigation Timeline: 5 item(s)
- Agent Routing & Cycles: 11 item(s)
- Containment Actions: 3 item(s)
- Recommendations: 4 item(s)
- Analyst Decisions: 1 item(s)
- Tool Result Summary: 10 item(s)

JSON export report item counts:
- MITRE Mapping: 3
- Investigation Timeline: 5
- Agent Routing & Cycles: 11
- Containment Actions: 3
- Recommendations: 4
- Analyst Decisions: 1
- Tool Result Summary: 10

Visible tool rows:

| Tool row | Tokens |
|---|---:|
| 05:00:31 PMVirusTotalEnrichment Agent12052ms965 tok | 965 |
| 05:00:55 PMAbuseIPDBEnrichment Agent23076ms875 tok | 875 |
| 05:01:06 PMActive DirectoryIdentity Investigation Agent9440ms844 tok | 844 |
| 05:01:26 PMOktaIdentity Investigation Agent19613ms846 tok | 846 |
| 05:01:43 PMEDREndpoint Investigation Agent16222ms969 tok | 969 |
| 05:01:56 PMSIEMLog Analysis Agent11577ms961 tok | 961 |
| 05:02:09 PMMicrosoft 365 AuditLog Analysis Agent13121ms975 tok | 975 |
| 05:02:28 PMAWS CloudTrailLog Analysis Agent18090ms967 tok | 967 |
| 05:02:43 PMServiceNowTicketing Agent13606ms974 tok | 974 |
| 05:02:49 PMJiraTicketing Agent5391ms809 tok | 809 |

Cyclic handoff evidence:

| From | To | Kind | Visible text |
|---|---|---|---|
| supervisor | triage | forward | 01Supervisor -> Triage Agentroute_initial_triageSupervisor starts triage because jsmith@ent.local, WKST-JSMITH-04, and ev-update-sync.net appear in the same alert cluster. |
| triage | enrichment | parallel | 02Triage Agent -> Enrichmentexpand_ioc_contextTriage finds enough malicious signal to enrich IP, domain, URL, and hash evidence. |
| enrichment | identity | forward | 03Enrichment -> Identityvalidate_identity_scopeThreat intel suggests the identity may be the attacker pivot rather than only the victim. |
| identity | endpoint | forward | 04Identity -> Endpointinspect_host_activityIdentity risk is high enough to inspect endpoint process ancestry and network sessions. |
| endpoint | log_analysis | forward | 05Endpoint -> Log Analysisreconstruct_timelineEndpoint artifacts need SIEM and cloud timeline correlation before containment. |
| log_analysis | enrichment | backtrack | 06Log Analysis -> EnrichmentCyclic back edgeMap-reduce logs expose a second-stage IOC, so Log Analysis routes back to Enrichment. |
| enrichment | identity | forward | 07Enrichment -> Identityreanalyze_identity_after_new_iocNew enrichment updates the user/session blast-radius hypothesis. |
| identity | endpoint | forward | 08Identity -> Endpointconfirm_host_after_identity_loopUpdated identity evidence requires a second endpoint check on the affected host. |
| endpoint | log_analysis | forward | 09Endpoint -> Log Analysisreduce_second_pass_logsEndpoint confirmation sends the graph back into log reduction for a final confidence score. |
| log_analysis | threat_intel | forward | 10Log Analysis -> Threat Intelmap_actor_ttpSecond-pass timeline has enough confidence for actor/TTP matching. |
| threat_intel | supervisor | backtrack | 11Threat Intel -> SupervisorCyclic back edgeThreat Intel returns the case to Supervisor for the final containment decision. |
| supervisor | containment | interrupt | 12Supervisor -> Containmentpause_for_human_approvalSupervisor chooses HITL containment after cyclic review raises confidence above threshold. |

Reporting rows:
- 05:00:19 PMGLM-5.1Supervisor Graph Orchestrator19457ms585 tok
- 05:03:11 PMGLM-5.1Reporting Agent16256ms7066 tok

Verification window:
- Started: 2026-05-04T21:59:56.022Z
- Finished: 2026-05-04T22:03:21.821Z
