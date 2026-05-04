const toolSpecs = {
  "/api/virustotal/lookup": {
    name: "VirusTotal",
    path: "/api/virustotal/lookup",
    method: "POST",
    purpose: "IP, hash, URL, and domain reputation with detections and vendor verdicts.",
    schemaHint: "Return attributes, last_analysis_stats, reputation, categories, tags, and related indicators."
  },
  "/api/abuseipdb/check": {
    name: "AbuseIPDB",
    path: "/api/abuseipdb/check",
    method: "POST",
    purpose: "IP abuse score, confidence, ISP, ASN, country, and recent abuse reports.",
    schemaHint: "Return abuseConfidenceScore, countryCode, isp, usageType, totalReports, and sampleReports."
  },
  "/api/activedirectory/user": {
    name: "Active Directory",
    path: "/api/activedirectory/user",
    method: "POST",
    purpose: "User, host, group, privileged access, last login, and directory relationship lookup.",
    schemaHint: "Return userPrincipalName, groups, adminTier, lastLogon, deviceTrust, manager, and anomalies."
  },
  "/api/servicenow/ticket": {
    name: "ServiceNow",
    path: "/api/servicenow/ticket",
    method: "POST",
    purpose: "Create or update an incident ticket with assignment, severity, SLA, and work notes.",
    schemaHint: "Return number, sys_id, priority, assignment_group, state, sla_due, work_notes, and url."
  },
  "/api/jira/issue": {
    name: "Jira",
    path: "/api/jira/issue",
    method: "POST",
    purpose: "Create security engineering follow-up tasks and link them to incident work.",
    schemaHint: "Return issueKey, project, issueType, priority, labels, assignee, status, and linkedIncident."
  },
  "/api/siem/search": {
    name: "SIEM",
    path: "/api/siem/search",
    method: "POST",
    purpose: "Splunk/QRadar-style event correlation, search query, and timeline reconstruction.",
    schemaHint: "Return query, earliest, latest, event_count, notable_events, timeline, and confidence."
  },
  "/api/shodan/host": {
    name: "Shodan",
    path: "/api/shodan/host",
    method: "POST",
    purpose: "Host exposure details, open ports, banners, certificates, and CVEs.",
    schemaHint: "Return ip_str, ports, hostnames, vulns, org, os, last_update, and banners."
  },
  "/api/firewall/block": {
    name: "Firewall",
    path: "/api/firewall/block",
    method: "POST",
    purpose: "Palo Alto-style block rule preview or execution for IP/domain containment.",
    schemaHint: "Return ruleName, action, target, zone, deviceGroup, commitRequired, and changeId."
  },
  "/api/edr/endpoint": {
    name: "EDR",
    path: "/api/edr/endpoint",
    method: "POST",
    purpose: "CrowdStrike-style endpoint telemetry, process tree, connections, hashes, and isolation status.",
    schemaHint: "Return device_id, hostname, sensorHealth, processes, networkConnections, files, and containment."
  },
  "/api/slack/notify": {
    name: "Slack",
    path: "/api/slack/notify",
    method: "POST",
    purpose: "SOC channel notification with incident summary, severity, owner, and action links.",
    schemaHint: "Return channel, message_ts, recipients, blocks, escalation_mentions, and deliveryStatus."
  },
  "/api/whois/lookup": {
    name: "WHOIS",
    path: "/api/whois/lookup",
    method: "POST",
    purpose: "Domain registration, registrar, creation date, expiration, nameservers, and privacy status.",
    schemaHint: "Return domainName, registrar, createdDate, expiresDate, nameservers, ageDays, and riskFlags."
  },
  "/api/okta/user-risk": {
    name: "Okta",
    path: "/api/okta/user-risk",
    method: "POST",
    purpose: "Identity risk, MFA posture, suspicious sessions, and recent application access.",
    schemaHint: "Return userId, riskLevel, mfaFactors, recentSessions, appAccess, impossibleTravel, and recommendation."
  },
  "/api/m365/audit": {
    name: "Microsoft 365 Audit",
    path: "/api/m365/audit",
    method: "POST",
    purpose: "Exchange, SharePoint, Entra ID, and audit log actions around the affected user.",
    schemaHint: "Return workload, operations, clientIPs, userAgents, mailRules, fileAccess, and suspiciousEvents."
  },
  "/api/cloudtrail/search": {
    name: "AWS CloudTrail",
    path: "/api/cloudtrail/search",
    method: "POST",
    purpose: "AWS CloudTrail API activity, IAM changes, source IPs, and suspicious cloud actions.",
    schemaHint: "Return accountId, region, events, sourceIPAddress, userIdentity, apiCalls, and guardrailFindings."
  }
};
const toolAliases = {
  virustotal: "/api/virustotal/lookup",
  abuseipdb: "/api/abuseipdb/check",
  activedirectory: "/api/activedirectory/user",
  servicenow: "/api/servicenow/ticket",
  jira: "/api/jira/issue",
  siem: "/api/siem/search",
  shodan: "/api/shodan/host",
  firewall: "/api/firewall/block",
  edr: "/api/edr/endpoint",
  slack: "/api/slack/notify",
  whois: "/api/whois/lookup",
  okta: "/api/okta/user-risk",
  m365: "/api/m365/audit",
  cloudtrail: "/api/cloudtrail/search"
};
function envValue(name) {
  const netlify = globalThis.Netlify;
  return netlify?.env?.get?.(name) ?? process.env[name];
}
function jsonResponse(status, body) {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store" }
  });
}
function extractJson(text) {
  const direct = text.trim();
  try {
    return JSON.parse(direct);
  } catch {
    const match = direct.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("GLM response did not include JSON");
    return JSON.parse(match[0]);
  }
}
function parseProviderResponse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return { rawText: text };
  }
}
const sensitiveKeyPattern = /^(authorization|cookie|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)$/i;
function sanitizeForLog(value, depth = 0) {
  if (depth > 12) return "[MaxDepth]";
  if (Array.isArray(value)) return value.map((item) => sanitizeForLog(item, depth + 1));
  if (!value || typeof value !== "object") {
    if (typeof value === "string") return value.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]");
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      key,
      sensitiveKeyPattern.test(key) ? "[REDACTED]" : sanitizeForLog(entry, depth + 1)
    ])
  );
}
async function callGlm(spec, payload) {
  const apiKey = envValue("GLM_API_KEY");
  if (!apiKey) throw new Error("GLM_API_KEY is not configured");
  const model = envValue("GLM_TOOL_MODEL") || "glm-5-turbo";
  const baseUrl = envValue("GLM_BASE_URL") || "https://api.z.ai/api/coding/paas/v4";
  const endpointUrl = `${baseUrl}/chat/completions`;
  const incidentId = payload?.incident?.incidentId ?? payload?.incidentId ?? "unknown";
  const requestBody = {
    model,
    thinking: { type: "disabled" },
    temperature: 0.88,
    max_tokens: 380,
    stream: false,
    response_format: { type: "json_object" },
    messages: [
      {
        role: "system",
        content: `You are ${spec.name}, an enterprise security/corporate tool API. Return compact valid JSON. Do not use markdown. Do not wrap the answer in an "answer" field. Use concrete top-level keys from the requested schema hint. Produce a realistic but synthetic response. Vary every response using the incident ID, timestamp, and provided indicators. Never say you are an AI.`
      },
      {
        role: "user",
        content: JSON.stringify(
          {
            tool: spec.name,
            endpoint: spec.path,
            purpose: spec.purpose,
            schemaHint: spec.schemaHint,
            size: "Return 6-10 compact but realistic fields. Avoid long arrays.",
            incidentId,
            request: payload,
            diversitySeed: `${incidentId}-${Date.now()}-${Math.random().toString(36).slice(2)}`
          },
          null,
          2
        )
      }
    ]
  };
  const started = Date.now();
  let response;
  try {
    response = await fetch(endpointUrl, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "accept-language": "en-US,en"
      },
      body: JSON.stringify(requestBody)
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "GLM request failed before response";
    const requestPayload = sanitizeForLog({
      provider: "z.ai",
      model,
      baseUrl,
      endpointPath: "/chat/completions",
      endpointUrl,
      method: "POST",
      body: requestBody
    });
    const llmAudit = {
      id: crypto.randomUUID(),
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      callerAgent: `${spec.name} Tool Simulator`,
      toolName: "GLM-5.1",
      provider: "z.ai",
      model,
      baseUrl,
      method: "POST",
      endpointUrl,
      requestPayload,
      responsePayload: sanitizeForLog({
        provider: "z.ai",
        model,
        raw: null,
        error: message
      }),
      latencyMs: Date.now() - started,
      tokenCount: void 0,
      usage: void 0,
      status: "error",
      type: "error"
    };
    const wrapped = error instanceof Error ? error : new Error(message);
    wrapped.llmAudit = llmAudit;
    throw wrapped;
  }
  const text = await response.text();
  const data = parseProviderResponse(text);
  const makeAudit = (result2, error, rawContent = text) => ({
    id: crypto.randomUUID(),
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    callerAgent: `${spec.name} Tool Simulator`,
    toolName: "GLM-5.1",
    provider: "z.ai",
    model: data?.model ?? model,
    baseUrl,
    method: "POST",
    endpointUrl,
    requestPayload: sanitizeForLog({
      provider: "z.ai",
      model,
      baseUrl,
      endpointPath: "/chat/completions",
      endpointUrl,
      method: "POST",
      body: requestBody
    }),
    rawResponsePayload: sanitizeForLog(data),
    parsedResponsePayload: sanitizeForLog(result2),
    responsePayload: sanitizeForLog({
      provider: "z.ai",
      model: data?.model ?? model,
      statusCode: response.status,
      statusText: response.statusText,
      raw: data,
      rawContent,
      parsedOutput: result2,
      normalizedOutput: result2,
      usage: data?.usage,
      error
    }),
    latencyMs: Date.now() - started,
    status: response.ok ? "ok" : "error",
    statusCode: response.status,
    statusText: response.statusText,
    tokenCount: data?.usage?.total_tokens,
    usage: data?.usage,
    type: response.ok ? "llm" : "error"
  });
  if (!response.ok) {
    const error = new Error(`GLM ${response.status}: ${text.slice(0, 220)}`);
    error.llmAudit = makeAudit(void 0, error.message);
    throw error;
  }
  const content = data?.choices?.[0]?.message?.content ?? "{}";
  let result;
  try {
    result = extractJson(content);
  } catch (error) {
    const parseError = error instanceof Error ? error : new Error("GLM response parse failed");
    parseError.llmAudit = makeAudit(void 0, parseError.message, content);
    throw parseError;
  }
  return {
    result,
    usage: data?.usage ?? {},
    model: data?.model ?? model,
    latencyMs: Date.now() - started,
    llmAudit: makeAudit(result, void 0, content)
  };
}
var tool_gateway_default = async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;
  const aliasPath = toolAliases[url.searchParams.get("tool") ?? ""];
  const spec = toolSpecs[path] ?? toolSpecs[aliasPath];
  if (!spec) return jsonResponse(404, { error: "Unknown tool endpoint", path });
  if (req.method !== "POST") return jsonResponse(405, { error: "Method not allowed" });
  let payload;
  try {
    payload = await req.json();
  } catch {
    return jsonResponse(400, { error: "Expected JSON body" });
  }
  try {
    const generated = await callGlm(spec, payload);
    return jsonResponse(200, {
      tool: spec.name,
      endpoint: spec.path,
      generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
      incidentId: payload?.incident?.incidentId ?? payload?.incidentId,
      model: generated.model,
      usage: generated.usage,
      latencyMs: generated.latencyMs,
      llmAudit: generated.llmAudit,
      data: generated.result
    });
  } catch (error) {
    const llmAudit = error instanceof Error ? error.llmAudit : void 0;
    return jsonResponse(502, {
      tool: spec.name,
      endpoint: spec.path,
      error: error instanceof Error ? error.message : "Tool generation failed",
      llmAudit
    });
  }
};
const config = {
  path: Object.keys(toolSpecs)
};
export {
  config,
  tool_gateway_default as default
};
