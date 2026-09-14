import { asArgumentsObject } from './lib/arguments';
import {
  AlertTriangle,
  ArrowRight,
  Layers3,
  CheckCircle2,
  Braces,
  Check,
  ChevronDown,
  Clock3,
  Download,
  FileText,
  GitBranch,
  History,
  Pause,
  Play,
  Radio,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Workflow,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { graphEdges, graphNodes, toolEndpoints } from "./data/graph";
import { buildRunExport, downloadJson, downloadReportPdf } from "./lib/export";
import { consumeSse } from "./lib/sse";
import type {
  AgentRoute,
  ApiLogEntry,
  ApprovalRequest,
  Checkpoint,
  FinalReport,
  HealthResponse,
  Incident,
  LlmEvidence,
  LlmMessage,
  RunState,
  SseEvent,
  TimelineEvent,
} from "./lib/types";

const initialRun: RunState = {
  runId: "",
  threadId: "",
  statuses: Object.fromEntries(graphNodes.map((node) => [node.id, "pending"])),
  timeline: [],
  apiLogs: [],
  routes: [],
  checkpoints: [],
  streamText: "",
};

const statusLabel = {
  pending: "Pending",
  running: "Running",
  complete: "Complete",
  failed: "Failed",
  paused: "Paused",
};

function shortTime(value?: string) {
  if (!value) return "--";
  return new Intl.DateTimeFormat("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "America/Chicago",
  }).format(new Date(value));
}

function duration(ms?: number) {
  if (!ms) return "0.0s";
  return `${(ms / 1000).toFixed(1)}s`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getString(value: unknown) {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function firstString(...values: unknown[]) {
  for (const value of values) {
    const stringValue = getString(value);
    if (stringValue) return stringValue;
  }
  return undefined;
}

function firstValue(...values: unknown[]) {
  for (const value of values) {
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

function messageList(value: unknown): LlmMessage[] | undefined {
  return Array.isArray(value) ? (value as LlmMessage[]) : undefined;
}

function findMessages(value: unknown): LlmMessage[] | undefined {
  if (!value || typeof value !== "object") return undefined;
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findMessages(item);
      if (found) return found;
    }
    return undefined;
  }

  const record = value as Record<string, unknown>;
  const messages = messageList(record.messages);
  if (messages?.length) return messages;

  for (const entry of Object.values(record)) {
    const found = findMessages(entry);
    if (found) return found;
  }
  return undefined;
}

function findPrompt(value: unknown): unknown {
  if (!value || typeof value !== "object") return undefined;
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findPrompt(item);
      if (found !== undefined) return found;
    }
    return undefined;
  }

  const record = value as Record<string, unknown>;
  if (typeof record.prompt === "string" && record.prompt.trim())
    return record.prompt;

  for (const entry of Object.values(record)) {
    const found = findPrompt(entry);
    if (found !== undefined) return found;
  }
  return undefined;
}

function inferProvider(log: ApiLogEntry) {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {};
  const evidence = log.llmEvidence;
  const explicit = firstString(
    log.provider,
    evidence?.provider,
    request.provider,
  );
  if (explicit) return explicit;
  if (/deepseek/i.test(`${log.toolName} ${log.endpointUrl}`)) return "DeepSeek";
  if (/fireworks/i.test(`${log.toolName} ${log.endpointUrl}`))
    return "Fireworks";
  if (/glm|z\.ai|api\.z\.ai/i.test(`${log.toolName} ${log.endpointUrl}`))
    return "Z.ai";
  return log.toolName;
}

function inferModel(log: ApiLogEntry) {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {};
  const response = isRecord(log.responsePayload) ? log.responsePayload : {};
  return firstString(
    log.model,
    log.llmEvidence?.model,
    request.model,
    response.model,
    log.toolName,
  );
}

function extractPrompt(log: ApiLogEntry, messages?: LlmMessage[]) {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {};
  const evidence = log.llmEvidence;
  const directPrompt = firstValue(
    log.prompt,
    evidence?.prompt,
    request.prompt,
    findPrompt(request),
  );
  if (directPrompt !== undefined) return directPrompt;
  const userMessage = [...(messages ?? [])]
    .reverse()
    .find((item) => item.role === "user");
  return userMessage?.content;
}

function buildLlmEvidence(log: ApiLogEntry): LlmEvidence {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {};
  const evidence = log.llmEvidence;
  const messages =
    messageList(log.messages) ??
    messageList(evidence?.messages) ??
    findMessages(request);
  const parsedResponsePayload = firstValue(
    log.parsedResponsePayload,
    evidence?.parsedResponsePayload,
    log.responsePayload,
  );

  return {
    provider: inferProvider(log),
    model: inferModel(log),
    endpoint: firstString(evidence?.endpoint, log.endpointUrl),
    method: firstString(evidence?.method, log.method),
    latencyMs: evidence?.latencyMs ?? log.latencyMs,
    status: evidence?.status ?? log.status,
    statusCode: evidence?.statusCode ?? log.statusCode,
    tokenCount: evidence?.tokenCount ?? log.tokenCount,
    prompt: extractPrompt(log, messages),
    messages,
    requestPayload: firstValue(evidence?.requestPayload, log.requestPayload),
    rawResponsePayload: firstValue(
      log.rawResponsePayload,
      evidence?.rawResponsePayload,
    ),
    parsedResponsePayload,
  };
}

function hasModelEvidence(log: ApiLogEntry) {
  return Boolean(
    log.type === "llm" ||
      log.provider ||
      log.model ||
      log.rawResponsePayload ||
      log.parsedResponsePayload ||
      log.llmEvidence,
  );
}

function normalizeApiLog(log: ApiLogEntry): ApiLogEntry {
  if (!hasModelEvidence(log)) return log;
  return {
    ...log,
    provider: log.provider ?? inferProvider(log),
    model: log.model ?? inferModel(log),
    llmEvidence: buildLlmEvidence(log),
  };
}

type EnterpriseTool = (typeof toolEndpoints)[number];

function numberValue(value: unknown) {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

function toolPayload(tool: EnterpriseTool, incident: Incident) {
  return {
    incident,
    tool: tool.name,
    callerAgent: tool.agent,
    endpoint: tool.endpoint,
    source: "langgraph-send-fanout",
    requestTimestamp: new Date().toISOString(),
    action: "investigate",
  };
}

function toolEvidenceLog(
  tool: EnterpriseTool,
  payload: Record<string, unknown>,
  body: unknown,
  responseStatus: number,
  responseStatusText: string,
  elapsedMs: number,
): ApiLogEntry {
  const responseBody = isRecord(body) ? body : {};
  const audit = isRecord(responseBody.llmAudit) ? responseBody.llmAudit : {};
  const tokenCount = numberValue(audit.tokenCount);
  const status =
    responseStatus >= 200 &&
    responseStatus < 300 &&
    audit.status === "ok" &&
    Boolean(tokenCount);
  const provider = firstString(audit.provider);
  const model = firstString(audit.model);
  const endpoint = firstString(audit.endpointUrl, audit.endpoint);
  const requestPayload = firstValue(audit.requestPayload, {});
  const rawResponsePayload = firstValue(audit.rawResponsePayload, responseBody);
  const parsedResponsePayload = firstValue(
    audit.parsedResponsePayload,
    responseBody.data,
    responseBody,
  );
  const statusCode = numberValue(audit.statusCode) ?? responseStatus;
  const statusText = firstString(audit.statusText) ?? responseStatusText;
  const latencyMs = numberValue(audit.latencyMs) ?? elapsedMs;

  return normalizeApiLog({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    callerAgent: tool.agent,
    toolName: tool.name,
    provider,
    model,
    method: "POST",
    endpointUrl: tool.endpoint,
    requestPayload: {
      toolEndpoint: {
        method: "POST",
        endpointUrl: tool.endpoint,
        body: payload,
      },
      llmRequest: requestPayload,
    },
    responsePayload: {
      toolEndpointResponse: responseBody,
      llmResponse: firstValue(audit.responsePayload, responseBody),
    },
    rawResponsePayload,
    parsedResponsePayload,
    latencyMs,
    tokenCount,
    statusCode,
    statusText,
    status: status ? "ok" : "error",
    type: status ? "tool" : "error",
    llmEvidence: {
      provider,
      model,
      endpoint,
      method: "POST",
      latencyMs,
      status: status ? "ok" : "error",
      statusCode,
      tokenCount,
      requestPayload,
      rawResponsePayload,
      parsedResponsePayload,
    },
  });
}

async function callEnterpriseTool(
  tool: EnterpriseTool,
  incident: Incident,
): Promise<ApiLogEntry> {
  const payload = toolPayload(tool, incident);
  const started = Date.now();
  try {
    const response = await fetch(tool.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await response
      .json()
      .catch(() => ({ error: "Tool endpoint returned non-JSON response" }));
    return toolEvidenceLog(
      tool,
      payload,
      body,
      response.status,
      response.statusText,
      Date.now() - started,
    );
  } catch (error) {
    return normalizeApiLog({
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      callerAgent: tool.agent,
      toolName: tool.name,
      method: "POST",
      endpointUrl: tool.endpoint,
      requestPayload: {
        toolEndpoint: {
          method: "POST",
          endpointUrl: tool.endpoint,
          body: payload,
        },
      },
      responsePayload: {
        error:
          error instanceof Error
            ? error.message
            : "Tool endpoint request failed",
      },
      latencyMs: Date.now() - started,
      status: "error",
      type: "error",
    });
  }
}

async function runEnterpriseToolFanout(
  incident: Incident,
  appendLogs: (logs: ApiLogEntry[]) => void,
  selectedTools: EnterpriseTool[] = toolEndpoints,
) {
  let nextTool = 0;
  const worker = async () => {
    while (nextTool < selectedTools.length) {
      const tool = selectedTools[nextTool++];
      const log = await callEnterpriseTool(tool, incident);
      appendLogs([log]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(3, selectedTools.length) }, worker));
}

function applyRunEvent(current: RunState, item: SseEvent): RunState {
  switch (item.event) {
    case "start": {
      const data = item.data as {
        runId: string;
        threadId: string;
        startedAt: string;
      };
      return {
        ...initialRun,
        runId: data.runId,
        threadId: data.threadId,
        startedAt: data.startedAt,
      };
    }
    case "node_start": {
      const data = item.data as { node: string; timestamp: string };
      return {
        ...current,
        activeNode: data.node,
        statuses: { ...current.statuses, [data.node]: "running" },
      };
    }
    case "node_complete": {
      const data = item.data as { node: string };
      return {
        ...current,
        activeNode: undefined,
        statuses: { ...current.statuses, [data.node]: "complete" },
      };
    }
    case "node_failed": {
      const data = item.data as { node: string; error: string };
      return {
        ...current,
        activeNode: undefined,
        statuses: { ...current.statuses, [data.node]: "failed" },
        timeline: [
          ...current.timeline,
          {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            title: `${data.node} failed`,
            detail: data.error,
            outcome: "error",
          },
        ],
      };
    }
    case "timeline":
      return {
        ...current,
        timeline: [...current.timeline, item.data as TimelineEvent],
      };
    case "agent_route":
      return {
        ...current,
        routes: [...current.routes, item.data as AgentRoute],
      };
    case "checkpoint":
      return {
        ...current,
        checkpoints: [...current.checkpoints, item.data as Checkpoint],
      };
    case "api_call":
      return {
        ...current,
        apiLogs: [
          ...current.apiLogs,
          normalizeApiLog(item.data as ApiLogEntry),
        ],
      };
    case "delta": {
      const data = item.data as { content: string };
      return { ...current, streamText: `${current.streamText}${data.content}` };
    }
    case "incident":
      return { ...current, incident: item.data as Incident };
    case "approval_required": {
      const approval = item.data as ApprovalRequest;
      return {
        ...current,
        approval,
        activeNode: "containment",
        statuses: { ...current.statuses, containment: "paused" },
      };
    }
    case "report":
      return { ...current, report: item.data as FinalReport };
    case "complete": {
      const data = item.data as { completedAt: string; mttrMs: number };
      return {
        ...current,
        completedAt: data.completedAt,
        mttrMs: data.mttrMs,
        activeNode: undefined,
      };
    }
    default:
      return current;
  }
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "hot" | "cool" | "ok";
}) {
  return (
    <div className={`metric ${tone ?? ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatusPill({
  children,
  tone,
}: {
  children: string;
  tone?: "ok" | "warn" | "bad" | "live";
}) {
  return <span className={`pill ${tone ?? ""}`}>{children}</span>;
}

function Header({
  health,
  running,
  onStart,
}: {
  health?: HealthResponse;
  running: boolean;
  onStart: () => void;
}) {
  const reachable =
    health &&
    String(health.status) !== "degraded" &&
    String(health.mode).startsWith("live-");
  return (
    <header className="topbar">
      <a
        className="brand"
        href="#workspace"
        aria-label="Sentinel investigation workspace"
      >
        <span className="brandMark">
          <ShieldAlert size={24} />
        </span>
        <div>
          <h1>
            SENTINEL<span> / SOC</span>
          </h1>
          <p>AI investigation workspace</p>
        </div>
      </a>
      <div className="topbar__right">
        <div
          className="providerStatus"
          title={health?.model ?? "Checking model availability"}
        >
          <span className={`statusDot ${reachable ? "ready" : ""}`} />
          <span>
            {!health
              ? "Checking provider"
              : reachable
                ? `${health.provider} reachable`
                : "Provider unavailable"}
          </span>
        </div>
        <button className="primary" onClick={onStart} disabled={running}>
          {running ? <Radio size={16} /> : <Play size={16} />}
          {running ? "Investigation active" : "Generate Incident"}
        </button>
      </div>
    </header>
  );
}

function IncidentCard({
  incident,
  onStart,
  running,
}: {
  incident?: Incident;
  onStart: () => void;
  running: boolean;
}) {
  if (!incident) {
    return (
      <section className="panel incident empty">
        <div className="emptyIllustration" aria-hidden="true">
          <span />
          <span />
          <ShieldAlert size={42} />
          <i className="scanCorner" />
        </div>
        <span className="eyebrow">YOUR NEXT INVESTIGATION</span>
        <h2>
          {running ? "Building your incident…" : "Every signal has a story."}
        </h2>
        <p>
          {running
            ? "The model is creating a synthetic scenario. Live progress, evidence, and analyst decisions will appear here as the investigation unfolds."
            : "Follow an AI investigation from the first alert to a reviewed response. Start with a synthetic incident, inspect the evidence, and make the containment decision."}
        </p>
        <button className="primary" onClick={onStart} disabled={running}>
          {running ? <Radio size={16} /> : <Sparkles size={16} />}
          {running ? "Generating scenario" : "Start first investigation"}
          {!running && <ArrowRight size={16} />}
        </button>
        <small>
          No setup required · Synthetic security data · Real AI reasoning
        </small>
      </section>
    );
  }

  return (
    <section className="panel incident">
      <div className="incident__header">
        <div>
          <span className="mono">{incident.incidentId}</span>
          <h2>{incident.incidentType}</h2>
        </div>
        <StatusPill tone={incident.severity === "Critical" ? "bad" : "warn"}>
          {incident.severity}
        </StatusPill>
      </div>
      <div className="incident__grid">
        <Metric
          label="Priority"
          value={`${incident.priorityScore}/10`}
          tone="hot"
        />
        <Metric label="Source" value={incident.initialAlertSource} />
        <Metric label="Department" value={incident.affectedDepartment} />
        <Metric label="MITRE" value={incident.mitreTechnique} tone="cool" />
      </div>
      <div className="kv">
        <span>User</span>
        <strong>{incident.affectedUser}</strong>
        <span>Host</span>
        <strong>{incident.affectedHost}</strong>
        <span>IP</span>
        <strong>{incident.affectedIp}</strong>
        <span>IOC domain</span>
        <strong>{incident.iocs.domain}</strong>
      </div>
      <pre className="logSnippet">{incident.rawLogSnippet}</pre>
    </section>
  );
}

const nodeLabel = new Map(graphNodes.map((node) => [node.id, node.label]));

function formatNode(value?: string) {
  if (!value) return "unknown";
  return nodeLabel.get(value) ?? value.replaceAll("_", " ");
}

function routeText(route: AgentRoute) {
  return `${formatNode(route.from)} -> ${formatNode(route.to)}`;
}

function GraphView({ run }: { run: RunState }) {
  const activeRouteIds = new Set(
    run.routes.map((route) => `${route.from}->${route.to}`),
  );
  const backtrackCount = run.routes.filter(
    (route) => route.kind === "backtrack",
  ).length;

  return (
    <section className="panel graphPanel">
      <div className="panel__title rowBetween">
        <span>
          <Workflow size={17} />
          Live LangGraph Execution
        </span>
        <StatusPill tone={backtrackCount > 0 ? "warn" : "ok"}>
          {backtrackCount > 0
            ? `${backtrackCount} cyclic back edges`
            : "Awaiting execution"}
        </StatusPill>
      </div>
      <div className="graphFrame">
        <div className="graph">
          <div className="graphEdges" aria-hidden="true">
            {graphEdges.map((edge) => {
              const from = graphNodes.find((node) => node.id === edge.from);
              const to = graphNodes.find((node) => node.id === edge.to);
              if (!from || !to) return null;
              const active = activeRouteIds.has(`${edge.from}->${edge.to}`);
              const x1 = `${(from.order + 0.5) * (100 / 6)}%`;
              const y1 = `${(from.lane + 0.5) * (100 / 3)}%`;
              const x2 = `${(to.order + 0.5) * (100 / 6)}%`;
              const y2 = `${(to.lane + 0.5) * (100 / 3)}%`;
              return (
                <svg
                  className={`graphEdge ${edge.kind} ${active ? "active" : ""}`}
                  key={edge.id}
                >
                  <line x1={x1} y1={y1} x2={x2} y2={y2} />
                </svg>
              );
            })}
          </div>
          {graphNodes.map((node) => {
            const status = run.statuses[node.id] ?? "pending";
            const routeHits = run.routes.filter(
              (route) => route.from === node.id || route.to === node.id,
            ).length;
            return (
              <div
                className={`graphNode ${status} ${run.activeNode === node.id ? "active" : ""} ${routeHits ? "routed" : ""}`}
                key={node.id}
                data-testid="graph-node"
                data-node-id={node.id}
                style={{
                  gridColumn: node.order + 1,
                  gridRow: node.lane + 1,
                }}
                title={node.description}
              >
                <span className="graphNode__capability">{node.capability}</span>
                <strong>{node.label}</strong>
                <small>{statusLabel[status]}</small>
                {routeHits ? <em>{routeHits} routes</em> : null}
              </div>
            );
          })}
        </div>
      </div>
      <RouteTrace routes={run.routes} />
    </section>
  );
}

function RouteTrace({ routes }: { routes: AgentRoute[] }) {
  return (
    <div className="routeTrace" data-testid="handoff-trace">
      <div className="routeTrace__header">
        <RefreshCw size={14} />
        <strong>Cyclic Handoff Trace</strong>
        <span>
          {routes.length ? `${routes.length} decisions` : "waiting for graph"}
        </span>
      </div>
      {routes.length === 0 ? (
        <p className="muted">
          The StateGraph will list every agent handoff, including back edges to
          earlier agents.
        </p>
      ) : (
        <div className="routeSteps">
          {routes.map((route, index) => (
            <div
              className={`routeStep ${route.kind}`}
              data-testid="handoff-row"
              data-from={route.from}
              data-to={route.to}
              data-kind={route.kind}
              key={route.id}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
              <strong>{routeText(route)}</strong>
              <small>
                {route.kind === "backtrack"
                  ? "Cyclic back edge"
                  : route.decision}
              </small>
              <p>{route.reason}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Checkpoints({
  checkpoints,
  onReplay,
  disabled,
}: {
  checkpoints: Checkpoint[];
  onReplay: (checkpoint: Checkpoint) => void;
  disabled: boolean;
}) {
  return (
    <section className="panel checkpoints">
      <div className="panel__title">
        <History size={17} />
        Snapshots & Alternate Analysis
      </div>
      <div className="checkpointList">
        {checkpoints.length === 0 ? (
          <p className="muted">
            Browser-held state snapshots appear after each node completes.
            Forking requests an alternate model analysis, rather than replaying
            a durable checkpoint.
          </p>
        ) : (
          checkpoints.map((item) => (
            <div
              className={`checkpoint ${item.node.includes("route") || item.node === "time_travel_fork" ? "cycle" : ""}`}
              data-testid="checkpoint-row"
              data-node={item.node}
              key={item.id}
            >
              <div>
                <span className="mono">{item.id}</span>
                <strong>{formatNode(item.node)}</strong>
                <small>{shortTime(item.timestamp)}</small>
              </div>
              <button
                className="ghost"
                disabled={disabled}
                onClick={() => onReplay(item)}
              >
                <GitBranch size={14} />
                Fork
              </button>
              <details>
                <summary>
                  <Braces size={14} /> State
                </summary>
                {isRecord(item.state.route) ? (
                  <div className="checkpointRoute">
                    <StatusPill
                      tone={
                        (item.state.route as unknown as AgentRoute).kind ===
                        "backtrack"
                          ? "warn"
                          : "ok"
                      }
                    >
                      {(item.state.route as unknown as AgentRoute).kind ===
                      "backtrack"
                        ? "Cyclic route"
                        : "Route"}
                    </StatusPill>
                    <strong>
                      {routeText(item.state.route as unknown as AgentRoute)}
                    </strong>
                    <p>{(item.state.route as unknown as AgentRoute).reason}</p>
                  </div>
                ) : null}
                {item.node === "time_travel_fork" ? (
                  <div className="checkpointRoute">
                    <StatusPill tone="warn">Replay branch</StatusPill>
                    <strong>
                      {String(item.state.branchName ?? "alternate branch")}
                    </strong>
                    <p>
                      {String(
                        item.state.changedDecision ??
                          item.state.nextAction ??
                          "Forked route reviewed",
                      )}
                    </p>
                  </div>
                ) : null}
                <pre>{JSON.stringify(item.state, null, 2)}</pre>
              </details>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function Timeline({ events }: { events: TimelineEvent[] }) {
  return (
    <section className="panel timeline">
      <div className="panel__title">
        <Clock3 size={17} />
        Investigation Timeline
      </div>
      <div className="timelineList">
        {events.length === 0 ? (
          <p className="muted">No events yet.</p>
        ) : (
          events.map((item) => (
            <div
              className={`timelineItem ${item.outcome} ${/cyclic|back edge|Forked/i.test(`${item.title} ${item.detail}`) ? "cycleRoute" : ""}`}
              key={item.id}
            >
              <span>{shortTime(item.timestamp)}</span>
              <div>
                <strong>{item.title}</strong>
                {/Forked/i.test(item.title) ? (
                  <small>Cycle: checkpoint -&gt; supervisor</small>
                ) : null}
                <p>{item.detail}</p>
                {item.durationMs ? (
                  <small>{duration(item.durationMs)}</small>
                ) : null}
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function formatPayload(
  value: unknown,
  emptyLabel = "Not included in this SSE log",
) {
  if (value === undefined || value === null) return emptyLabel;
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function PayloadPanel({
  title,
  value,
  emptyLabel,
}: {
  title: string;
  value: unknown;
  emptyLabel?: string;
}) {
  return (
    <div className="payloadPanel">
      <strong>{title}</strong>
      <pre>{formatPayload(value, emptyLabel)}</pre>
    </div>
  );
}

function LlmLogDetails({ log }: { log: ApiLogEntry }) {
  const evidence = buildLlmEvidence(log);
  const promptMessages = evidence.messages?.length
    ? evidence.messages
    : evidence.prompt;

  return (
    <div className="llmEvidence">
      <div className="evidenceMeta">
        <span>
          <small>Provider / model</small>
          <strong>
            {evidence.provider ?? "--"} / {evidence.model ?? "--"}
          </strong>
        </span>
        <span>
          <small>Endpoint</small>
          <strong>{evidence.endpoint ?? log.endpointUrl}</strong>
        </span>
        <span>
          <small>Latency</small>
          <strong>{evidence.latencyMs ?? 0}ms</strong>
        </span>
        <span>
          <small>Status</small>
          <strong>
            {evidence.statusCode ? `${evidence.statusCode} ` : ""}
            {evidence.status ?? log.status}
          </strong>
        </span>
        <span>
          <small>Tokens</small>
          <strong>{evidence.tokenCount ?? 0}</strong>
        </span>
      </div>
      <div className="apiPayloads llmPayloads">
        <PayloadPanel
          title="Prompt / messages"
          value={promptMessages}
          emptyLabel="Prompt/messages were not included in this SSE log entry."
        />
        <PayloadPanel title="Request payload" value={evidence.requestPayload} />
        <PayloadPanel
          title="Raw response payload"
          value={evidence.rawResponsePayload}
          emptyLabel="Raw provider response was not included separately in this SSE log entry."
        />
        <PayloadPanel
          title="Parsed response payload"
          value={evidence.parsedResponsePayload}
        />
      </div>
    </div>
  );
}

function ApiLog({ logs }: { logs: ApiLogEntry[] }) {
  const [filter, setFilter] = useState("all");
  const filtered =
    filter === "all" ? logs : logs.filter((log) => log.type === filter);

  return (
    <section className="panel apiLog">
      <div className="panel__title rowBetween">
        <span>
          <Radio size={17} />
          API Transparency Log
        </span>
        <select
          aria-label="Filter API evidence"
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        >
          <option value="all">All calls</option>
          <option value="llm">LLM</option>
          <option value="tool">Tools</option>
          <option value="human">Human</option>
          <option value="routing">Routing</option>
          <option value="error">Errors</option>
        </select>
      </div>
      <div className="apiRows">
        {filtered.length === 0 ? (
          <p className="muted">
            Model requests and synthetic tool calls appear here with request
            payloads, responses, and latency.
          </p>
        ) : (
          filtered.map((log) => (
            <details
              className={`apiRow ${log.type} ${/route|handoff|Time Travel/i.test(`${log.callerAgent} ${log.toolName}`) ? "cycleEvidence" : ""}`}
              data-testid="api-row"
              data-type={log.type}
              data-agent={log.callerAgent}
              key={log.id}
            >
              <summary>
                <span>{shortTime(log.timestamp)}</span>
                <strong>{log.toolName}</strong>
                <small>{log.callerAgent}</small>
                <em>{log.latencyMs}ms</em>
                <b>{log.tokenCount ?? 0} tok</b>
              </summary>
              {hasModelEvidence(log) ? (
                <LlmLogDetails log={log} />
              ) : (
                <div className="apiPayloads">
                  <PayloadPanel
                    title="Request payload"
                    value={log.requestPayload}
                  />
                  <PayloadPanel
                    title="Response payload"
                    value={log.responsePayload}
                  />
                </div>
              )}
            </details>
          ))
        )}
      </div>
    </section>
  );
}

function ApprovalCard({
  request,
  onDecision,
  disabled,
  statusMessage,
  onRetryEvidence,
}: {
  request: ApprovalRequest;
  onDecision: (
    decision: "approve" | "reject" | "edit",
    args?: Record<string, unknown>,
  ) => void;
  disabled?: boolean;
  statusMessage?: string;
  onRetryEvidence?: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [args, setArgs] = useState(
    JSON.stringify(asArgumentsObject(request.toolArguments), null, 2),
  );
  const [argumentError, setArgumentError] = useState<string>();

  return (
    <aside className="approval" role="region" aria-label="Analyst approval">
      <div className="approval__header">
        <Pause size={18} />
        <div>
          <strong>Review containment</strong>
          <span>{request.actionName}</span>
        </div>
        <StatusPill tone={request.severity === "Critical" ? "bad" : "warn"}>
          {request.severity}
        </StatusPill>
      </div>
      <p>{request.riskJustification}</p>
      <small className="syntheticNotice">
        Simulated containment only. No corporate systems are connected.
      </small>
      {statusMessage ? (
        <p className="approval__status">{statusMessage}</p>
      ) : null}
      {onRetryEvidence ? (
        <button className="ghost" onClick={onRetryEvidence}>
          <RefreshCw size={14} />
          Retry missing evidence
        </button>
      ) : null}
      <div className="kv compact">
        <span>Target</span>
        <strong>{request.target}</strong>
        <span>Review suggested by</span>
        <strong>{shortTime(request.expiresAt)}</strong>
      </div>
      {editing ? (
        <textarea
          aria-label="Containment arguments JSON"
          value={args}
          onChange={(event) => {
            setArgs(event.target.value);
            setArgumentError(undefined);
          }}
        />
      ) : (
        <pre>{JSON.stringify(asArgumentsObject(request.toolArguments), null, 2)}</pre>
      )}
      {argumentError ? (
        <p className="argumentError" role="alert">
          {argumentError}
        </p>
      ) : null}
      <div className="approval__buttons">
        <button
          className="danger"
          disabled={disabled}
          onClick={() => onDecision("reject")}
        >
          <X size={15} />
          Reject
        </button>
        <button
          className="ghost"
          disabled={disabled}
          onClick={() => setEditing((value) => !value)}
        >
          {editing ? <ChevronDown size={15} /> : <Braces size={15} />}
          {editing ? "Review" : "Edit"}
        </button>
        <button
          className="primary"
          disabled={disabled}
          onClick={() => {
            if (!editing) {
              onDecision("approve");
              return;
            }
            try {
              const parsed: unknown = JSON.parse(args);
              if (!isRecord(parsed)) {
                setArgumentError(
                  "Enter a JSON object with named arguments before approving.",
                );
                return;
              }
              onDecision("edit", parsed);
            } catch {
              setArgumentError(
                "Invalid JSON. Check quotes and commas before approving.",
              );
            }
          }}
        >
          <Check size={15} />
          {editing ? "Edit & Approve" : "Approve"}
        </button>
      </div>
    </aside>
  );
}

function Report({
  incident,
  report,
  run,
  toolEvidenceComplete,
  toolEvidenceCount,
}: {
  incident?: Incident;
  report?: FinalReport;
  run: RunState;
  toolEvidenceComplete: boolean;
  toolEvidenceCount: number;
}) {
  const mitreMapping = safeList(report?.mitreMapping);
  const recommendations = safeList(report?.recommendations);
  const timelineItems = safeList(report?.timeline);
  const agentRouting = safeList(report?.agentRouting);
  const containmentActions = safeList(report?.containmentActions);
  const analystDecisions = safeList(report?.analystDecisions);
  const toolResultSummary = safeList(report?.toolResultSummary);
  const waitingText = (() => {
    if (run.statuses.reporting === "running")
      return "The Reporting Agent is generating the final RCA now.";
    if (run.approval && !toolEvidenceComplete) {
      return `Collecting AI-generated synthetic tool evidence before report generation: ${toolEvidenceCount}/${toolEndpoints.length} complete.`;
    }
    if (run.approval)
      return "Approval is ready. The Reporting Agent will compile the RCA after analyst decision.";
    return "The Reporting Agent compiles the final RCA after containment and notifications finish.";
  })();

  return (
    <section className="panel report" id="final-report">
      <div className="panel__title rowBetween">
        <span>
          <FileText size={17} />
          Final Incident Report
        </span>
        <span className="actions">
          <button
            className="ghost"
            onClick={() =>
              downloadJson("soc-run-export.json", buildRunExport(run))
            }
          >
            <Download size={14} />
            JSON
          </button>
          <button
            className="ghost"
            disabled={!report}
            onClick={() => downloadReportPdf(incident, report)}
          >
            <Download size={14} />
            PDF
          </button>
        </span>
      </div>
      {!report ? (
        <p className="muted">{waitingText}</p>
      ) : (
        <div className="reportBody">
          <h3>Executive Summary</h3>
          <p>{report.executiveSummary}</p>
          <h3>Root Cause</h3>
          <p>{report.rootCause}</p>
          <h3>MITRE Mapping</h3>
          <ReportList items={mitreMapping} />
          <h3>Investigation Timeline</h3>
          <ReportList items={timelineItems} />
          <h3>Agent Routing &amp; Cycles</h3>
          <ReportList items={agentRouting} />
          <h3>Containment Actions</h3>
          <ReportList items={containmentActions} />
          <h3>Recommendations</h3>
          <ReportList items={recommendations} />
          <h3>Analyst Decisions</h3>
          <ReportList items={analystDecisions} />
          <h3>Tool Result Summary</h3>
          <ReportList items={toolResultSummary} />
        </div>
      )}
    </section>
  );
}

function ReportList({ items }: { items: string[] }) {
  if (items.length === 0)
    return <p className="muted">No report entries captured.</p>;
  return (
    <ul>
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

function DemoGuide({ health }: { health?: HealthResponse }) {
  return (
    <section className="panel guide">
      <div className="panel__title">
        <Layers3 size={17} />
        How it works<span className="sectionIndex">01—03</span>
      </div>
      <div className="guideSteps">
        <div>
          <span>01</span>
          <div>
            <h3>Start with a signal</h3>
            <p>
              Generate a synthetic security incident with context, indicators,
              and an initial alert.
            </p>
          </div>
        </div>
        <div>
          <span>02</span>
          <div>
            <h3>Follow the investigation</h3>
            <p>
              Watch agents triage, enrich, and correlate evidence. Inspect each
              decision in the execution graph.
            </p>
          </div>
        </div>
        <div>
          <span>03</span>
          <div>
            <h3>You make the call</h3>
            <p>
              Approve, reject, or edit containment. Export the report or fork a
              snapshot to request an alternate analysis.
            </p>
          </div>
        </div>
      </div>
      <div className="boundaryNote">
        <ShieldAlert size={17} />
        <div>
          <strong>A safe space to investigate</strong>
          <p>
            Tool responses, security events, tickets, and containment are
            synthetic. AI calls and LangGraph orchestration are real.
          </p>
        </div>
      </div>
      <details className="systemDetails">
        <summary>Runtime details</summary>
        <div className="guideGrid">
          <p>
            {health?.provider ?? "Checking provider"} ·{" "}
            {health?.model ?? "Model not yet verified"}
          </p>
          <code>{health?.endpoint ?? "Checking endpoint"}</code>
          <p>
            {health?.healthDetail ??
              "Provider availability has not been verified yet."}
          </p>
          <p>
            StateGraph · specialist subgraphs · human approval · browser
            snapshots · alternate analysis
          </p>
        </div>
      </details>
    </section>
  );
}

function App() {
  const [activeTab, setActiveTab] = useState<
    "overview" | "graph" | "evidence" | "report"
  >("overview");
  const [health, setHealth] = useState<HealthResponse>();
  const [run, setRun] = useState<RunState>(initialRun);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string>();
  const [toolFanoutState, setToolFanoutState] = useState<
    "idle" | "running" | "complete"
  >("idle");
  const fanoutRunRef = useRef(0);

  useEffect(() => {
    fetch("/api/health")
      .then((response) => response.json())
      .then(setHealth)
      .catch(() => {
        setHealth({
          service: "soc-ai-agent-demo",
          status: "degraded",
          mode: "missing-key",
          provider: "Unavailable",
          model: "Unverified",
          endpoint: "unavailable",
          checkedAt: new Date().toISOString(),
          capabilities: {},
          models: [],
        });
      });
  }, []);

  const toolCount = useMemo(
    () => run.apiLogs.filter((log) => log.type === "tool").length,
    [run.apiLogs],
  );
  const toolEvidenceComplete =
    toolFanoutState === "complete" && toolCount >= toolEndpoints.length;
  const toolMetric = useMemo(() => {
    const denominator = Math.max(toolEndpoints.length, toolCount);
    return `${toolCount}/${denominator}`;
  }, [toolCount]);
  const tokenCount = useMemo(
    () => run.apiLogs.reduce((sum, log) => sum + (log.tokenCount ?? 0), 0),
    [run.apiLogs],
  );

  const handleEvent = (item: SseEvent) => {
    if (item.event === "report") setActiveTab("report");
    if (item.event === "error") {
      const data = item.data as { message: string };
      setError(data.message);
    }
    if (item.event === "incident") {
      const incident = item.data as Incident;
      const fanoutId = fanoutRunRef.current;
      setToolFanoutState("running");
      void runEnterpriseToolFanout(incident, (logs) => {
        if (
          fanoutId === fanoutRunRef.current &&
          logs.some((log) => log.status !== "ok")
        )
          setError(
            "A synthetic tool request failed. Once collection finishes, retry missing evidence in the approval panel.",
          );
        setRun((current) => {
          if (fanoutId !== fanoutRunRef.current) return current;
          return { ...current, apiLogs: [...current.apiLogs, ...logs] };
        });
      }).finally(() => {
        if (fanoutId === fanoutRunRef.current) setToolFanoutState("complete");
      });
    }
    setRun((current) => applyRunEvent(current, item));
  };

  const startRun = async () => {
    if (running || run.approval || toolFanoutState === "running") return;
    setActiveTab("overview");
    fanoutRunRef.current += 1;
    setRunning(true);
    setError(undefined);
    setToolFanoutState("idle");
    setRun(initialRun);
    try {
      const response = await fetch("/api/agent-run", { method: "POST" });
      await consumeSse(response, handleEvent);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Agent run failed");
    } finally {
      setRunning(false);
    }
  };

  const retryMissingEvidence = async () => {
    if (!run.incident || running || toolFanoutState === "running") return;
    const successfulTools = new Set(
      run.apiLogs
        .filter((log) => log.type === "tool" && log.status === "ok")
        .map((log) => log.toolName),
    );
    const missingTools = toolEndpoints.filter(
      (tool) => !successfulTools.has(tool.name),
    );
    if (!missingTools.length) return;
    setError(undefined);
    setToolFanoutState("running");
    try {
      await runEnterpriseToolFanout(
        run.incident,
        (logs) => {
          if (logs.some((log) => log.status !== "ok"))
            setError(
              "A synthetic tool request failed again. Inspect its error in Evidence & replay before retrying.",
            );
          setRun((current) => ({
            ...current,
            apiLogs: [...current.apiLogs, ...logs],
          }));
        },
        missingTools,
      );
    } finally {
      setToolFanoutState("complete");
    }
  };

  const decide = async (
    decision: "approve" | "reject" | "edit",
    editedArguments?: Record<string, unknown>,
  ) => {
    if (!run.approval) return;
    const approval = run.approval;
    if (!toolEvidenceComplete) {
      setError(
        `Final report is waiting for all ${toolEndpoints.length} synthetic tool calls to finish.`,
      );
      return;
    }
    setRunning(true);
    setError(undefined);
    const payload = {
      decision,
      editedArguments,
      approval,
      checkpoints: run.checkpoints,
      routes: run.routes,
      timeline: run.timeline,
      apiLogs: run.apiLogs,
      streamText: run.streamText,
    };
    const humanLog: ApiLogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      callerAgent: "SOC Analyst",
      toolName: "Human Approval",
      method: "POST",
      endpointUrl: "/api/resume-run",
      requestPayload: payload,
      responsePayload: { decision },
      latencyMs: 0,
      status: "ok",
      type: "human",
    };
    setRun((current) => ({
      ...current,
      approval: undefined,
      apiLogs: [...current.apiLogs, humanLog],
      statuses: {
        ...current.statuses,
        containment: decision === "reject" ? "failed" : "running",
      },
    }));
    try {
      let resumeFailed = false;
      const response = await fetch("/api/resume-run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      await consumeSse(response, (item) => {
        if (item.event === "error") resumeFailed = true;
        handleEvent(item);
      });
      if (resumeFailed) {
        setRun((current) => ({
          ...current,
          approval,
          statuses: { ...current.statuses, containment: "paused" },
        }));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Resume failed");
      setRun((current) => ({
        ...current,
        approval,
        statuses: { ...current.statuses, containment: "paused" },
      }));
    } finally {
      setRunning(false);
    }
  };

  const replay = async (checkpoint: Checkpoint) => {
    if (
      !run.incident ||
      running ||
      run.approval ||
      toolFanoutState === "running"
    )
      return;
    setRunning(true);
    setError(undefined);
    try {
      const response = await fetch("/api/replay-run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          checkpoint,
          incident: run.incident,
          threadId: run.threadId,
        }),
      });
      await consumeSse(response, handleEvent);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Replay failed");
    } finally {
      setRunning(false);
    }
  };

  const busy =
    running || toolFanoutState === "running" || Boolean(run.approval);
  const completedNodes = Object.values(run.statuses).filter(
    (value) => value === "complete",
  ).length;
  const currentStage = run.report ? 4 : run.approval ? 2 : run.incident ? 1 : 0;
  const progressLabel = error
    ? "Investigation needs attention"
    : run.report
      ? "Report ready for review"
      : run.approval
        ? toolEvidenceComplete
          ? "Your decision is needed"
          : "Gathering synthetic tool evidence"
        : running
          ? `In progress · ${formatNode(run.activeNode || "incident_generator")}`
          : run.runId
            ? "Investigation paused"
            : "Ready when you are";
  const tabs = [
    { id: "overview" as const, label: "Overview", icon: ShieldAlert },
    { id: "graph" as const, label: "Execution graph", icon: Workflow },
    { id: "evidence" as const, label: "Evidence & replay", icon: History },
    { id: "report" as const, label: "Report", icon: FileText },
  ];

  return (
    <main id="workspace">
      <Header health={health} running={busy} onStart={startRun} />
      <section className="heroBand">
        <div className="heroCopy">
          <span className="eyebrow">
            <span className="tinySquare" /> SECURITY OPERATIONS / INVESTIGATION
            LAB
          </span>
          <h2>
            From alert to <em>understanding.</em>
          </h2>
          <p>
            A transparent investigation. A human decision. Every step, accounted
            for.
          </p>
        </div>
        <div className="heroSeal" aria-hidden="true">
          <ShieldAlert size={44} />
          <span>
            ANALYST
            <br />
            IN CONTROL
          </span>
        </div>
      </section>
      <div className="workspaceStatus">
        <div className="runState" aria-live="polite">
          <span
            className={`statusDot ${error ? "error" : busy ? "pulse" : run.report ? "ready" : ""}`}
          />
          <strong>{progressLabel}</strong>
        </div>
        <span className="mono">
          {run.runId ? `RUN ${run.runId.slice(0, 12)}` : "NEW SESSION"}
          <span className="centralTime"> · Central Time</span>
        </span>
      </div>
      {error ? (
        <div className="errorBanner" role="alert">
          <AlertTriangle size={20} />
          <div>
            <strong>We couldn’t finish this step.</strong>
            <p>{error}</p>
            <small>
              {run.approval
                ? "Your approval is preserved. Review the error before trying again."
                : "Review the evidence for details, then generate a new incident to retry."}
            </small>
          </div>
        </div>
      ) : null}
      <section className="metricsRow" aria-label="Investigation metrics">
        <Metric
          label="State snapshots"
          value={`${run.checkpoints.length}`}
          tone="cool"
        />
        <Metric label="Synthetic tool evidence" value={toolMetric} />
        <Metric
          label="Model tokens recorded"
          value={tokenCount.toLocaleString()}
        />
        <Metric
          label="Investigation duration"
          value={run.completedAt && run.startedAt ? duration(Math.max(0, Date.parse(run.completedAt) - Date.parse(run.startedAt))) : "—"}
        />
      </section>
      <nav
        className="workspaceTabs"
        role="tablist"
        aria-label="Investigation views"
      >
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            id={`tab-${id}`}
            role="tab"
            aria-selected={activeTab === id}
            aria-controls={`view-${id}`}
            tabIndex={activeTab === id ? 0 : -1}
            className={activeTab === id ? "selected" : ""}
            onClick={() => setActiveTab(id)}
            onKeyDown={(event) => {
              if (
                ["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)
              ) {
                event.preventDefault();
                const current = tabs.findIndex((tab) => tab.id === id);
                const next =
                  event.key === "Home"
                    ? 0
                    : event.key === "End"
                      ? tabs.length - 1
                      : (current +
                          (event.key === "ArrowRight" ? 1 : -1) +
                          tabs.length) %
                        tabs.length;
                setActiveTab(tabs[next].id);
                document.getElementById(`tab-${tabs[next].id}`)?.focus();
              }
            }}
          >
            <Icon size={16} />
            {label}
            {id === "report" && run.report ? (
              <span className="tabBadge">Ready</span>
            ) : null}
          </button>
        ))}
      </nav>
      <div
        role="tabpanel"
        id="view-overview"
        aria-labelledby="tab-overview"
        hidden={activeTab !== "overview"}
      >
        <div className="layout">
          <div className="mainColumn">
            <IncidentCard
              incident={run.incident}
              onStart={startRun}
              running={busy}
            />
            <section className="panel journeyPanel">
              <div className="panel__title">
                <Workflow size={17} />
                Investigation path
                <span className="sectionIndex">
                  {completedNodes}/{graphNodes.length} nodes complete
                </span>
              </div>
              <div className="journey">
                {["Generate", "Investigate", "Review", "Report"].map(
                  (label, index) => (
                    <div
                      className={`${index < currentStage ? "complete" : ""} ${index === currentStage && busy ? "current" : ""}`}
                      key={label}
                    >
                      <span>
                        {index < currentStage ? (
                          <Check size={15} />
                        ) : (
                          String(index + 1).padStart(2, "0")
                        )}
                      </span>
                      <strong>{label}</strong>
                    </div>
                  ),
                )}
              </div>
              <button
                className="textButton"
                onClick={() => setActiveTab("graph")}
              >
                Inspect the execution graph <ArrowRight size={15} />
              </button>
            </section>
          </div>
          <div className="sideColumn">
            <DemoGuide health={health} />
            {run.report ? (
              <section className="panel reportReady">
                <CheckCircle2 size={25} />
                <h3>Your report is ready.</h3>
                <p>
                  Review the findings, analyst decisions, and recommended next
                  steps.
                </p>
                <button
                  className="primary"
                  onClick={() => setActiveTab("report")}
                >
                  Read the report <ArrowRight size={15} />
                </button>
              </section>
            ) : null}
          </div>
        </div>
      </div>
      <div
        role="tabpanel"
        id="view-graph"
        aria-labelledby="tab-graph"
        hidden={activeTab !== "graph"}
      >
        <div className="viewIntro">
          <h2>Follow the reasoning.</h2>
          <p>
            Live node status, specialist handoffs, and cycles through the
            investigation.
          </p>
        </div>
        <GraphView run={run} />
      </div>
      <div
        role="tabpanel"
        id="view-evidence"
        aria-labelledby="tab-evidence"
        hidden={activeTab !== "evidence"}
      >
        <div className="viewIntro">
          <h2>Nothing behind the curtain.</h2>
          <p>
            Inspect the model calls and synthetic tool evidence. Fork a browser
            snapshot for alternate analysis after the current run finishes.
          </p>
        </div>
        <ApiLog logs={run.apiLogs} />
        <div className="layout lower">
          <Timeline events={run.timeline} />
          <Checkpoints
            checkpoints={run.checkpoints}
            onReplay={replay}
            disabled={busy}
          />
        </div>
        {run.streamText ? (
          <details className="panel stream">
            <summary>
              <Radio size={17} /> Model streaming output
            </summary>
            <pre>{run.streamText}</pre>
          </details>
        ) : null}
      </div>
      <div
        role="tabpanel"
        id="view-report"
        aria-labelledby="tab-report"
        hidden={activeTab !== "report"}
      >
        <div className="viewIntro">
          <h2>The complete picture.</h2>
          <p>Findings, response decisions, and next steps, ready to share.</p>
        </div>
        <Report
          incident={run.incident}
          report={run.report}
          run={run}
          toolEvidenceComplete={toolEvidenceComplete}
          toolEvidenceCount={toolCount}
        />
      </div>
      <footer className="workspaceFooter">
        <span>
          <ShieldAlert size={14} /> SENTINEL / SOC
        </span>
        <p>
          Synthetic security environment · Real LangGraph orchestration · Human
          oversight
        </p>
      </footer>
      {run.approval ? (
        <ApprovalCard
          key={run.approval.runId}
          request={run.approval}
          onDecision={decide}
          onRetryEvidence={
            toolFanoutState === "complete" && !toolEvidenceComplete && !running
              ? retryMissingEvidence
              : undefined
          }
          disabled={running || !toolEvidenceComplete}
          statusMessage={
            toolEvidenceComplete
              ? "Evidence is ready. Your decision will resume the investigation and generate the report."
              : toolFanoutState === "complete"
                ? `Some tool calls failed (${toolCount}/${toolEndpoints.length} complete). Retry only the missing evidence to continue.`
                : `Collecting synthetic tool evidence: ${toolCount}/${toolEndpoints.length} complete.`
          }
        />
      ) : null}
    </main>
  );
}

function safeList(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item));
  if (typeof value === "string" && value.trim()) return [value];
  return [];
}

export default App;
