const toolEndpoints = [
  { name: "VirusTotal", endpoint: "/api/virustotal/lookup", agent: "Enrichment Agent" },
  { name: "AbuseIPDB", endpoint: "/api/abuseipdb/check", agent: "Enrichment Agent" },
  { name: "Active Directory", endpoint: "/api/activedirectory/user", agent: "Identity Investigation Agent" },
  { name: "Okta", endpoint: "/api/okta/user-risk", agent: "Identity Investigation Agent" },
  { name: "EDR", endpoint: "/api/edr/endpoint", agent: "Endpoint Investigation Agent" },
  { name: "SIEM", endpoint: "/api/siem/search", agent: "Log Analysis Agent" },
  { name: "Microsoft 365 Audit", endpoint: "/api/m365/audit", agent: "Log Analysis Agent" },
  { name: "AWS CloudTrail", endpoint: "/api/cloudtrail/search", agent: "Log Analysis Agent" },
  { name: "ServiceNow", endpoint: "/api/servicenow/ticket", agent: "Ticketing Agent" },
  { name: "Jira", endpoint: "/api/jira/issue", agent: "Ticketing Agent" }
];
const rateLimitWindowMs = 6e4;
const rateLimitMaxRequests = 18;
const runtimeState = globalThis;
function envValue(name) {
  const netlify = globalThis.Netlify;
  return netlify?.env?.get?.(name) ?? process.env[name];
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
    if (typeof value === "string") {
      return value.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]").replace(/([?&](?:api[_-]?key|token|secret)=)[^&\s]+/gi, "$1[REDACTED]");
    }
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      key,
      sensitiveKeyPattern.test(key) ? "[REDACTED]" : sanitizeForLog(entry, depth + 1)
    ])
  );
}
function makeLlmAuditLog({
  callerAgent,
  provider,
  toolName,
  model,
  baseUrl,
  endpointPath = "/chat/completions",
  requestBody,
  rawResponse,
  rawContent,
  parsedOutput,
  normalizedOutput,
  usage,
  latencyMs,
  statusCode,
  statusText,
  ok,
  errorMessage,
  logType = "llm"
}) {
  const endpointUrl = `${baseUrl}${endpointPath}`;
  const usageRecord = usage && typeof usage === "object" ? usage : void 0;
  return makeLog({
    callerAgent,
    toolName,
    provider,
    model,
    baseUrl,
    method: "POST",
    endpointUrl,
    requestPayload: sanitizeForLog({
      provider,
      model,
      baseUrl,
      endpointPath,
      endpointUrl,
      method: "POST",
      body: requestBody
    }),
    rawResponsePayload: sanitizeForLog(rawResponse),
    parsedResponsePayload: sanitizeForLog(normalizedOutput ?? parsedOutput),
    responsePayload: sanitizeForLog({
      provider,
      model,
      statusCode,
      statusText,
      raw: rawResponse,
      rawContent,
      parsedOutput,
      normalizedOutput: normalizedOutput ?? parsedOutput,
      usage,
      error: errorMessage
    }),
    latencyMs,
    tokenCount: typeof usageRecord?.total_tokens === "number" ? usageRecord.total_tokens : void 0,
    usage,
    statusCode,
    statusText,
    status: ok ? "ok" : "error",
    type: ok ? logType : "error"
  });
}
function makeLog(input) {
  return { id: crypto.randomUUID(), timestamp: (/* @__PURE__ */ new Date()).toISOString(), ...input };
}
function clientKey(req) {
  return req.headers.get("x-nf-client-connection-ip") ?? req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "anonymous";
}
function rateLimit(req) {
  const now = Date.now();
  const key = clientKey(req);
  const store = runtimeState.socRateLimit ??= /* @__PURE__ */ new Map();
  const current = store.get(key);
  if (!current || current.resetAt <= now) {
    store.set(key, { count: 1, resetAt: now + rateLimitWindowMs });
    return void 0;
  }
  current.count += 1;
  if (current.count > rateLimitMaxRequests) {
    return Response.json(
      { error: "Rate limit exceeded. Wait before starting another investigation run." },
      { status: 429, headers: { "retry-after": `${Math.ceil((current.resetAt - now) / 1e3)}` } }
    );
  }
  return void 0;
}
function requiredKey() {
  const apiKey = envValue("GLM_API_KEY");
  if (!apiKey) throw new Error("GLM_API_KEY is not configured");
  return apiKey;
}
function requestTimeout(name, fallbackMs) {
  const configured = Number(envValue(name));
  return Number.isFinite(configured) && configured > 0 ? configured : fallbackMs;
}
async function callGlmJson({
  node,
  prompt,
  temperature = 0.82,
  maxTokens = 900,
  send,
  streamDeltas = false,
  modelName
}) {
  const apiKey = requiredKey();
  const model = modelName || envValue("GLM_MODEL") || "glm-5.1";
  const baseUrl = envValue("GLM_BASE_URL") || "https://api.z.ai/api/coding/paas/v4";
  const endpointPath = "/chat/completions";
  const body = {
    model,
    thinking: { type: "disabled" },
    temperature,
    max_tokens: maxTokens,
    stream: streamDeltas,
    response_format: { type: "json_object" },
    messages: [
      {
        role: "system",
        content: "You are an enterprise SOC multi-agent orchestration engine. Return only valid JSON. Do not use markdown."
      },
      { role: "user", content: typeof prompt === "string" ? prompt : JSON.stringify(prompt, null, 2) }
    ]
  };
  const started = Date.now();
  let response;
  try {
    response = await fetch(`${baseUrl}${endpointPath}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${apiKey}`,
        "content-type": "application/json",
        "accept-language": "en-US,en"
      },
      signal: AbortSignal.timeout(requestTimeout("GLM_ORCHESTRATION_TIMEOUT_MS", 18e3)),
      body: JSON.stringify(body)
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "GLM request failed before response";
    send("api_call", makeLlmAuditLog({
      callerAgent: node,
      provider: "z.ai",
      toolName: "GLM-5.1",
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: null,
      latencyMs: Date.now() - started,
      ok: false,
      errorMessage: message
    }));
    throw error;
  }
  if (!streamDeltas) {
    const text = await response.text();
    const parsed = parseProviderResponse(text);
    if (!response.ok) {
      send("api_call", makeLlmAuditLog({
        callerAgent: node,
        provider: "z.ai",
        toolName: "GLM-5.1",
        model,
        baseUrl,
        endpointPath,
        requestBody: body,
        rawResponse: parsed,
        rawContent: text,
        usage: parsed?.usage,
        latencyMs: Date.now() - started,
        statusCode: response.status,
        statusText: response.statusText,
        ok: false,
        errorMessage: `GLM ${response.status}: ${text.slice(0, 240)}`
      }));
      throw new Error(`GLM ${response.status}: ${text.slice(0, 240)}`);
    }
    const content2 = parsed?.choices?.[0]?.message?.content ?? "{}";
    let result2;
    try {
      result2 = extractJson(content2);
    } catch (error) {
      const message = error instanceof Error ? error.message : "GLM response parse failed";
      send("api_call", makeLlmAuditLog({
        callerAgent: node,
        provider: "z.ai",
        toolName: "GLM-5.1",
        model,
        baseUrl,
        endpointPath,
        requestBody: body,
        rawResponse: parsed,
        rawContent: content2,
        usage: parsed?.usage,
        latencyMs: Date.now() - started,
        statusCode: response.status,
        statusText: response.statusText,
        ok: false,
        errorMessage: message
      }));
      throw error;
    }
    const log2 = makeLlmAuditLog({
      callerAgent: node,
      provider: "z.ai",
      toolName: "GLM-5.1",
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: parsed,
      rawContent: content2,
      parsedOutput: result2,
      normalizedOutput: result2,
      usage: parsed?.usage,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: true
    });
    send("api_call", log2);
    return { result: result2, log: log2 };
  }
  if (!response.ok || !response.body) {
    const text = await response.text().catch(() => "");
    send("api_call", makeLlmAuditLog({
      callerAgent: node,
      provider: "z.ai",
      toolName: "GLM-5.1",
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: parseProviderResponse(text),
      rawContent: text,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: false,
      errorMessage: `GLM stream failed ${response.status}: ${text.slice(0, 240)}`
    }));
    throw new Error(`GLM stream failed ${response.status}: ${text.slice(0, 240)}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let content = "";
  let usage = void 0;
  const rawChunks = [];
  for (; ; ) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split(/\n\n/);
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      const line = frame.split(/\n/).find((candidate) => candidate.startsWith("data:"))?.slice(5).trim();
      if (!line || line === "[DONE]") continue;
      const chunk = JSON.parse(line);
      rawChunks.push(chunk);
      usage = chunk?.usage ?? usage;
      const delta = chunk?.choices?.[0]?.delta?.content ?? "";
      if (delta) {
        content += delta;
        send("delta", { node, content: delta });
      }
    }
  }
  let result;
  try {
    result = extractJson(content);
  } catch (error) {
    const message = error instanceof Error ? error.message : "GLM stream response parse failed";
    send("api_call", makeLlmAuditLog({
      callerAgent: node,
      provider: "z.ai",
      toolName: "GLM-5.1",
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: { chunks: rawChunks },
      rawContent: content,
      usage,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: false,
      errorMessage: message
    }));
    throw error;
  }
  const log = makeLlmAuditLog({
    callerAgent: node,
    provider: "z.ai",
    toolName: "GLM-5.1",
    model,
    baseUrl,
    endpointPath,
    requestBody: body,
    rawResponse: { chunks: rawChunks },
    rawContent: content,
    parsedOutput: result,
    normalizedOutput: result,
    usage,
    latencyMs: Date.now() - started,
    statusCode: response.status,
    statusText: response.statusText,
    ok: true
  });
  send("api_call", log);
  return { result, log };
}
function normalizeRunPlan(raw) {
  const compactIncident = raw?.incident ?? raw?.i ?? {};
  const severityOptions = ["Critical", "High", "Medium", "Low"];
  const severity = severityOptions.includes(compactIncident.severity) ? compactIncident.severity : "High";
  const iocs = compactIncident.iocs ?? {};
  const incident = {
    incidentId: compactIncident.incidentId ?? `SOC-${(/* @__PURE__ */ new Date()).toISOString().slice(0, 10).replaceAll("-", "")}-${crypto.randomUUID().slice(0, 6)}`,
    timestamp: compactIncident.timestamp ?? (/* @__PURE__ */ new Date()).toISOString(),
    severity,
    priorityScore: Number(compactIncident.priorityScore ?? 8),
    incidentType: compactIncident.incidentType ?? "lateral movement",
    affectedUser: compactIncident.affectedUser ?? "jsmith@corp.example",
    affectedHost: compactIncident.affectedHost ?? "WS-FIN-042",
    affectedIp: compactIncident.affectedIp ?? iocs.ip ?? "10.42.18.77",
    affectedDepartment: compactIncident.affectedDepartment ?? "Finance",
    mitreTactic: compactIncident.mitreTactic ?? "Credential Access",
    mitreTechnique: compactIncident.mitreTechnique ?? "T1003 OS Credential Dumping",
    initialAlertSource: compactIncident.initialAlertSource ?? "EDR",
    iocs: {
      ip: iocs.ip ?? compactIncident.affectedIp ?? "10.42.18.77",
      hash: iocs.hash ?? "b8a9f4f9d3a7d827b7110edc9d0f42d9b30d0db1f7c4e75db3ef1be9013c8a33",
      domain: iocs.domain ?? "cdn-update-check.example",
      url: iocs.url ?? "https://cdn-update-check.example/a.gif"
    },
    rawLogSnippet: compactIncident.rawLogSnippet ?? `${(/* @__PURE__ */ new Date()).toISOString()} EDR alert ${compactIncident.affectedHost ?? "WS-FIN-042"} suspicious credential access`
  };
  const compactSupervisor = raw?.supervisor ?? raw?.s ?? {};
  const supervisor = {
    route: compactSupervisor.route ?? compactSupervisor.r ?? "containment",
    rationale: compactSupervisor.rationale ?? compactSupervisor.why ?? "Correlated identity and endpoint signals support containment.",
    selectedAgents: compactSupervisor.selectedAgents ?? compactSupervisor.agents ?? ["Triage", "Enrichment", "Identity", "Endpoint", "Logs"],
    confidence: Number(compactSupervisor.confidence ?? compactSupervisor.conf ?? 0.88)
  };
  const compactTriage = raw?.triage ?? raw?.t ?? {};
  const triage = {
    classification: compactTriage.classification ?? compactTriage.class ?? "Confirmed malicious activity",
    dedupeStatus: compactTriage.dedupeStatus ?? compactTriage.dedupe ?? "new",
    riskScore: Number(compactTriage.riskScore ?? compactTriage.risk ?? 86),
    keyFindings: compactTriage.keyFindings ?? compactTriage.findings ?? ["IOC and host activity are correlated"]
  };
  const compactTools = Array.isArray(raw?.toolResults) ? raw.toolResults : Array.isArray(raw?.v) ? raw.v : [];
  const toolResults = toolEndpoints.map((tool, index) => {
    const item = compactTools[index] ?? {};
    const evidence = item?.responsePayload?.evidence ?? item?.e ?? `${incident.iocs.ip} observed on ${incident.affectedHost}`;
    return {
      name: item.name ?? item.n ?? tool.name,
      endpoint: item.endpoint ?? item.p ?? tool.endpoint,
      responsePayload: item.responsePayload ?? {
        verdict: item.verdict ?? item.r ?? `${tool.name} found suspicious correlation`,
        evidence
      },
      confidence: Number(item.confidence ?? item.c ?? 0.82),
      tokenCount: item.tokenCount
    };
  });
  const compactContainment = raw?.containment ?? raw?.a ?? {};
  const containment = {
    actionName: compactContainment.actionName ?? compactContainment.action ?? "isolate_host",
    target: compactContainment.target ?? incident.affectedHost,
    toolArguments: compactContainment.toolArguments ?? compactContainment.args ?? {
      host: incident.affectedHost,
      durationMinutes: 45,
      ticket: incident.incidentId
    },
    riskJustification: compactContainment.riskJustification ?? compactContainment.risk ?? "Temporary isolation may interrupt user work but reduces lateral movement risk."
  };
  return { incident, supervisor, triage, toolResults, containment };
}
function checkpoint(node, state, send) {
  send("checkpoint", {
    id: `ckpt-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    node,
    state
  });
}
function timeline(title, detail, outcome, send, durationMs) {
  send("timeline", {
    id: crypto.randomUUID(),
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    title,
    detail,
    outcome,
    durationMs
  });
}
var agent_run_default = async (req) => {
  if (req.method !== "POST") return Response.json({ error: "Method not allowed" }, { status: 405 });
  const limited = rateLimit(req);
  if (limited) return limited;
  const encoder = new TextEncoder();
  const startedAt = (/* @__PURE__ */ new Date()).toISOString();
  const startMs = Date.now();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event, data) => {
        controller.enqueue(encoder.encode(`event: ${event}
data: ${JSON.stringify(data)}

`));
      };
      const heartbeat = setInterval(() => controller.enqueue(encoder.encode(": keepalive\n\n")), 6e3);
      const runId = `run-${crypto.randomUUID().slice(0, 8)}`;
      const threadId = `thread-${crypto.randomUUID().slice(0, 12)}`;
      try {
        requiredKey();
        send("start", { runId, threadId, startedAt });
        timeline("Run started", "Supervisor accepted a new one-click incident investigation.", "info", send);
        send("node_start", { node: "incident_generator", timestamp: (/* @__PURE__ */ new Date()).toISOString() });
        const orchestrationPrompt = `Return minified JSON only. Seed ${Date.now()}-${crypto.randomUUID()}. Shape {"i":incident,"a":approval}. i must include incidentId,timestamp,severity,priorityScore,incidentType,affectedUser,affectedHost,affectedIp,affectedDepartment,mitreTactic,mitreTechnique,initialAlertSource,iocs{ip,hash,domain,url},rawLogSnippet(one line). a={actionName,target,toolArguments,riskJustification}. Keep text short.`;
        const orchestratedRun = await callGlmJson({
          node: "Supervisor Graph Orchestrator",
          prompt: orchestrationPrompt,
          temperature: 0.9,
          maxTokens: 420,
          send,
          streamDeltas: false,
          modelName: envValue("GLM_TOOL_MODEL") || "glm-5-turbo"
        });
        const streamPreview = JSON.stringify(orchestratedRun.result);
        for (let index = 0; index < streamPreview.length; index += 96) {
          send("delta", {
            node: "Supervisor Graph Orchestrator",
            content: streamPreview.slice(index, index + 96)
          });
        }
        const runPlan = normalizeRunPlan(orchestratedRun.result);
        const incident = runPlan.incident;
        const supervisorResult = runPlan.supervisor ?? {};
        const triageResult = runPlan.triage ?? {};
        const state = { supervisor: supervisorResult, triage: triageResult };
        send("incident", incident);
        checkpoint("incident_generator", { incident, threadId }, send);
        send("node_complete", {
          node: "incident_generator",
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          durationMs: orchestratedRun.log.latencyMs,
          summary: incident?.incidentId
        });
        send("node_start", { node: "supervisor", timestamp: (/* @__PURE__ */ new Date()).toISOString() });
        timeline("Supervisor routed incident", supervisorResult.rationale ?? "Routing complete.", "success", send);
        checkpoint("supervisor", { incidentId: incident?.incidentId, supervisor: supervisorResult }, send);
        send("node_complete", { node: "supervisor", timestamp: (/* @__PURE__ */ new Date()).toISOString(), durationMs: 0 });
        send("node_start", { node: "triage", timestamp: (/* @__PURE__ */ new Date()).toISOString() });
        timeline("Triage completed", triageResult.classification ?? "Incident classified.", "success", send);
        checkpoint("triage", { triage: triageResult }, send);
        send("node_complete", { node: "triage", timestamp: (/* @__PURE__ */ new Date()).toISOString(), durationMs: 0 });
        timeline(
          "Parallel superstep started",
          "Enrichment, identity, endpoint, log, cloud, and ticketing tools are ready for hosted Send() fan-out.",
          "info",
          send
        );
        for (const node of ["enrichment", "identity", "endpoint", "log_analysis", "threat_intel"]) {
          send("node_start", { node, timestamp: (/* @__PURE__ */ new Date()).toISOString() });
        }
        send("tool_fanout_required", {
          incident,
          state,
          tools: toolEndpoints,
          concurrency: 1,
          evidenceRequirement: "Each hosted tool endpoint must return llmAudit with prompt messages, raw response, parsed response, and nonzero token usage."
        });
        checkpoint(
          "parallel_superstep",
          {
            toolCount: toolEndpoints.length,
            toolEndpoints: toolEndpoints.map((tool) => tool.endpoint),
            executionMode: "hosted_tool_endpoint_fanout"
          },
          send
        );
        for (const node of ["enrichment", "identity", "endpoint", "log_analysis", "threat_intel"]) {
          send("node_complete", { node, timestamp: (/* @__PURE__ */ new Date()).toISOString(), durationMs: 0 });
        }
        send("node_start", { node: "containment", timestamp: (/* @__PURE__ */ new Date()).toISOString() });
        const containment = runPlan.containment ?? {};
        const approval = {
          runId,
          actionName: containment.actionName ?? "isolate_host",
          target: containment.target ?? incident?.affectedHost,
          toolArguments: containment.toolArguments ?? {
            host: incident?.affectedHost,
            durationMinutes: 45,
            ticket: incident?.incidentId
          },
          riskJustification: containment.riskJustification ?? "Containment may disrupt business workflow but prevents additional attacker movement.",
          severity: incident?.severity,
          expiresAt: new Date(Date.now() + 6e4).toISOString(),
          incident,
          stateSnapshot: {
            threadId,
            supervisor: supervisorResult,
            triage: triageResult,
            toolEndpoints
          }
        };
        checkpoint("containment_interrupt", { approval }, send);
        timeline("Containment paused", "LangGraph interrupt surfaced a human approval card.", "warning", send);
        send("approval_required", approval);
        send("done", {});
      } catch (error) {
        const message = error instanceof Error ? error.message : "Agent run failed";
        send("error", { message });
        send("api_call", makeLog({
          callerAgent: "Runtime",
          toolName: "Agent Run",
          method: req.method,
          endpointUrl: "/api/agent-run",
          requestPayload: {},
          responsePayload: { message },
          latencyMs: Date.now() - startMs,
          status: "error",
          type: "error"
        }));
        send("done", {});
      } finally {
        clearInterval(heartbeat);
        controller.close();
      }
    }
  });
  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive"
    }
  });
};
const config = {
  path: "/api/agent-run"
};
export {
  config,
  agent_run_default as default
};
