# Final Report Production Proof

Generated: 2026-05-04T17:27:08.029Z

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
- Initial live app: docs/evidence/netlify-cyclic-test-01-initial.png
- Approval card waiting for tool evidence: docs/evidence/netlify-cyclic-test-02-approval-waiting-tools.png
- Ten LLM-backed tool rows visible: docs/evidence/netlify-cyclic-test-03-tool-llm-evidence.png
- Cyclic graph state: docs/evidence/netlify-cyclic-test-03a-cyclic-graph.png
- Cyclic handoff trace: docs/evidence/netlify-cyclic-test-03b-cyclic-handoff-trace.png
- Handoff checkpoint state: docs/evidence/netlify-cyclic-test-03c-handoff-checkpoint-state.png
- Routing API evidence: docs/evidence/netlify-cyclic-test-03d-routing-api-evidence.png
- Final report rendered: docs/evidence/netlify-cyclic-test-04-final-report.png
- Replay proof after checkpoint fork: docs/evidence/netlify-cyclic-test-05-replay-proof.png

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

Visible tool rows:

| Tool row | Tokens |
|---|---:|
| 12:25:11 PMVirusTotalEnrichment Agent5163ms900 tok | 900 |
| 12:25:15 PMAbuseIPDBEnrichment Agent3183ms832 tok | 832 |
| 12:25:19 PMActive DirectoryIdentity Investigation Agent3271ms801 tok | 801 |
| 12:25:35 PMOktaIdentity Investigation Agent15511ms930 tok | 930 |
| 12:25:50 PMEDREndpoint Investigation Agent13563ms938 tok | 938 |
| 12:26:03 PMSIEMLog Analysis Agent12304ms930 tok | 930 |
| 12:26:10 PMMicrosoft 365 AuditLog Analysis Agent6184ms943 tok | 943 |
| 12:26:18 PMAWS CloudTrailLog Analysis Agent6933ms938 tok | 938 |
| 12:26:26 PMServiceNowTicketing Agent7908ms944 tok | 944 |
| 12:26:31 PMJiraTicketing Agent3890ms777 tok | 777 |

Cyclic handoff evidence:

| From | To | Kind | Visible text |
|---|---|---|---|
| supervisor | triage | forward | 01Supervisor -> Triage Agentroute_initial_triageSupervisor starts triage because jsmith@ent.local, WS-FIN-042, and evil-update-services.com appear in the same alert cluster. |
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
- 12:25:06 PMGLM-5.1Supervisor Graph Orchestrator8050ms587 tok
- 12:26:55 PMGLM-5.1Reporting Agent19527ms6811 tok

Verification window:
- Started: 2026-05-04T17:24:56.540Z
- Finished: 2026-05-04T17:27:08.029Z
