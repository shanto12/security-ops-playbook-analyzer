import {
  AlertTriangle,
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
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { graphEdges, graphNodes, toolEndpoints } from './data/graph'
import { buildRunExport, downloadJson, downloadReportPdf } from './lib/export'
import { consumeSse } from './lib/sse'
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
} from './lib/types'

const initialRun: RunState = {
  runId: '',
  threadId: '',
  statuses: Object.fromEntries(graphNodes.map((node) => [node.id, 'pending'])),
  timeline: [],
  apiLogs: [],
  routes: [],
  checkpoints: [],
  streamText: '',
}

const statusLabel = {
  pending: 'Pending',
  running: 'Running',
  complete: 'Complete',
  failed: 'Failed',
  paused: 'Paused',
}

function shortTime(value?: string) {
  if (!value) return '--'
  return new Intl.DateTimeFormat('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(value))
}

function duration(ms?: number) {
  if (!ms) return '0.0s'
  return `${(ms / 1000).toFixed(1)}s`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function getString(value: unknown) {
  return typeof value === 'string' && value.trim() ? value : undefined
}

function firstString(...values: unknown[]) {
  for (const value of values) {
    const stringValue = getString(value)
    if (stringValue) return stringValue
  }
  return undefined
}

function firstValue(...values: unknown[]) {
  for (const value of values) {
    if (value !== undefined && value !== null) return value
  }
  return undefined
}

function messageList(value: unknown): LlmMessage[] | undefined {
  return Array.isArray(value) ? (value as LlmMessage[]) : undefined
}

function findMessages(value: unknown): LlmMessage[] | undefined {
  if (!value || typeof value !== 'object') return undefined
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findMessages(item)
      if (found) return found
    }
    return undefined
  }

  const record = value as Record<string, unknown>
  const messages = messageList(record.messages)
  if (messages?.length) return messages

  for (const entry of Object.values(record)) {
    const found = findMessages(entry)
    if (found) return found
  }
  return undefined
}

function findPrompt(value: unknown): unknown {
  if (!value || typeof value !== 'object') return undefined
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findPrompt(item)
      if (found !== undefined) return found
    }
    return undefined
  }

  const record = value as Record<string, unknown>
  if (typeof record.prompt === 'string' && record.prompt.trim()) return record.prompt

  for (const entry of Object.values(record)) {
    const found = findPrompt(entry)
    if (found !== undefined) return found
  }
  return undefined
}

function inferProvider(log: ApiLogEntry) {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {}
  const evidence = log.llmEvidence
  const explicit = firstString(log.provider, evidence?.provider, request.provider)
  if (explicit) return explicit
  if (/fireworks/i.test(`${log.toolName} ${log.endpointUrl}`)) return 'Fireworks'
  if (/glm|z\.ai|api\.z\.ai/i.test(`${log.toolName} ${log.endpointUrl}`)) return 'Z.ai'
  return log.toolName
}

function inferModel(log: ApiLogEntry) {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {}
  const response = isRecord(log.responsePayload) ? log.responsePayload : {}
  return firstString(log.model, log.llmEvidence?.model, request.model, response.model, log.toolName)
}

function extractPrompt(log: ApiLogEntry, messages?: LlmMessage[]) {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {}
  const evidence = log.llmEvidence
  const directPrompt = firstValue(log.prompt, evidence?.prompt, request.prompt, findPrompt(request))
  if (directPrompt !== undefined) return directPrompt
  const userMessage = [...(messages ?? [])].reverse().find((item) => item.role === 'user')
  return userMessage?.content
}

function buildLlmEvidence(log: ApiLogEntry): LlmEvidence {
  const request = isRecord(log.requestPayload) ? log.requestPayload : {}
  const evidence = log.llmEvidence
  const messages = messageList(log.messages) ?? messageList(evidence?.messages) ?? findMessages(request)
  const parsedResponsePayload = firstValue(log.parsedResponsePayload, evidence?.parsedResponsePayload, log.responsePayload)

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
    rawResponsePayload: firstValue(log.rawResponsePayload, evidence?.rawResponsePayload),
    parsedResponsePayload,
  }
}

function hasModelEvidence(log: ApiLogEntry) {
  return Boolean(
    log.type === 'llm' ||
      log.provider ||
      log.model ||
      log.rawResponsePayload ||
      log.parsedResponsePayload ||
      log.llmEvidence,
  )
}

function normalizeApiLog(log: ApiLogEntry): ApiLogEntry {
  if (!hasModelEvidence(log)) return log
  return {
    ...log,
    provider: log.provider ?? inferProvider(log),
    model: log.model ?? inferModel(log),
    llmEvidence: buildLlmEvidence(log),
  }
}

type EnterpriseTool = (typeof toolEndpoints)[number]

function numberValue(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function toolPayload(tool: EnterpriseTool, incident: Incident) {
  return {
    incident,
    tool: tool.name,
    callerAgent: tool.agent,
    endpoint: tool.endpoint,
    source: 'langgraph-send-fanout',
    requestTimestamp: new Date().toISOString(),
    action: 'investigate',
  }
}

function toolEvidenceLog(
  tool: EnterpriseTool,
  payload: Record<string, unknown>,
  body: unknown,
  responseStatus: number,
  responseStatusText: string,
  elapsedMs: number,
): ApiLogEntry {
  const responseBody = isRecord(body) ? body : {}
  const audit = isRecord(responseBody.llmAudit) ? responseBody.llmAudit : {}
  const tokenCount = numberValue(audit.tokenCount)
  const status = responseStatus >= 200 && responseStatus < 300 && audit.status === 'ok' && Boolean(tokenCount)
  const provider = firstString(audit.provider)
  const model = firstString(audit.model)
  const endpoint = firstString(audit.endpointUrl, audit.endpoint)
  const requestPayload = firstValue(audit.requestPayload, {})
  const rawResponsePayload = firstValue(audit.rawResponsePayload, responseBody)
  const parsedResponsePayload = firstValue(audit.parsedResponsePayload, responseBody.data, responseBody)
  const statusCode = numberValue(audit.statusCode) ?? responseStatus
  const statusText = firstString(audit.statusText) ?? responseStatusText
  const latencyMs = numberValue(audit.latencyMs) ?? elapsedMs

  return normalizeApiLog({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    callerAgent: tool.agent,
    toolName: tool.name,
    provider,
    model,
    method: 'POST',
    endpointUrl: tool.endpoint,
    requestPayload: {
      toolEndpoint: {
        method: 'POST',
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
    status: status ? 'ok' : 'error',
    type: status ? 'tool' : 'error',
    llmEvidence: {
      provider,
      model,
      endpoint,
      method: 'POST',
      latencyMs,
      status: status ? 'ok' : 'error',
      statusCode,
      tokenCount,
      requestPayload,
      rawResponsePayload,
      parsedResponsePayload,
    },
  })
}

async function callEnterpriseTool(tool: EnterpriseTool, incident: Incident): Promise<ApiLogEntry> {
  const payload = toolPayload(tool, incident)
  const started = Date.now()
  try {
    const response = await fetch(tool.endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const body = await response.json().catch(() => ({ error: 'Tool endpoint returned non-JSON response' }))
    return toolEvidenceLog(tool, payload, body, response.status, response.statusText, Date.now() - started)
  } catch (error) {
    return normalizeApiLog({
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      callerAgent: tool.agent,
      toolName: tool.name,
      method: 'POST',
      endpointUrl: tool.endpoint,
      requestPayload: { toolEndpoint: { method: 'POST', endpointUrl: tool.endpoint, body: payload } },
      responsePayload: { error: error instanceof Error ? error.message : 'Tool endpoint request failed' },
      latencyMs: Date.now() - started,
      status: 'error',
      type: 'error',
    })
  }
}

async function callEnterpriseToolWithRetry(tool: EnterpriseTool, incident: Incident) {
  let lastLog: ApiLogEntry | undefined
  for (let attempt = 0; attempt < 5; attempt += 1) {
    lastLog = await callEnterpriseTool(tool, incident)
    if (lastLog.status === 'ok' && lastLog.tokenCount && lastLog.tokenCount > 0) return lastLog
    await wait(1800 + attempt * 2200)
  }
  return lastLog as ApiLogEntry
}

async function runEnterpriseToolFanout(
  incident: Incident,
  appendLogs: (logs: ApiLogEntry[]) => void,
) {
  for (const tool of toolEndpoints) {
    const log = await callEnterpriseToolWithRetry(tool, incident)
    appendLogs([log])
    await wait(650)
  }
}

function applyRunEvent(current: RunState, item: SseEvent): RunState {
  switch (item.event) {
    case 'start': {
      const data = item.data as { runId: string; threadId: string; startedAt: string }
      return {
        ...initialRun,
        runId: data.runId,
        threadId: data.threadId,
        startedAt: data.startedAt,
      }
    }
    case 'node_start': {
      const data = item.data as { node: string; timestamp: string }
      return {
        ...current,
        activeNode: data.node,
        statuses: { ...current.statuses, [data.node]: 'running' },
      }
    }
    case 'node_complete': {
      const data = item.data as { node: string }
      return {
        ...current,
        activeNode: undefined,
        statuses: { ...current.statuses, [data.node]: 'complete' },
      }
    }
    case 'node_failed': {
      const data = item.data as { node: string; error: string }
      return {
        ...current,
        activeNode: undefined,
        statuses: { ...current.statuses, [data.node]: 'failed' },
        timeline: [
          ...current.timeline,
          {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            title: `${data.node} failed`,
            detail: data.error,
            outcome: 'error',
          },
        ],
      }
    }
    case 'timeline':
      return { ...current, timeline: [...current.timeline, item.data as TimelineEvent] }
    case 'agent_route':
      return { ...current, routes: [...current.routes, item.data as AgentRoute] }
    case 'checkpoint':
      return { ...current, checkpoints: [...current.checkpoints, item.data as Checkpoint] }
    case 'api_call':
      return { ...current, apiLogs: [...current.apiLogs, normalizeApiLog(item.data as ApiLogEntry)] }
    case 'delta': {
      const data = item.data as { content: string }
      return { ...current, streamText: `${current.streamText}${data.content}` }
    }
    case 'incident':
      return { ...current, incident: item.data as Incident }
    case 'approval_required': {
      const approval = item.data as ApprovalRequest
      return {
        ...current,
        approval,
        activeNode: 'containment',
        statuses: { ...current.statuses, containment: 'paused' },
      }
    }
    case 'report':
      return { ...current, report: item.data as FinalReport }
    case 'complete': {
      const data = item.data as { completedAt: string; mttrMs: number }
      return {
        ...current,
        completedAt: data.completedAt,
        mttrMs: data.mttrMs,
        activeNode: undefined,
      }
    }
    default:
      return current
  }
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: 'hot' | 'cool' | 'ok' }) {
  return (
    <div className={`metric ${tone ?? ''}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function StatusPill({ children, tone }: { children: string; tone?: 'ok' | 'warn' | 'bad' | 'live' }) {
  return <span className={`pill ${tone ?? ''}`}>{children}</span>
}

function Header({
  health,
  running,
  onStart,
}: {
  health?: HealthResponse
  running: boolean
  onStart: () => void
}) {
  return (
    <header className="topbar">
      <div className="brand">
        <span className="brandMark">
          <ShieldAlert size={20} />
        </span>
        <div>
          <h1>SOC AI Agent Demo</h1>
          <p>LangGraph incident investigation pipeline, powered by GLM-5.1</p>
        </div>
      </div>
      <div className="topbar__right">
        <StatusPill tone={health?.mode === 'live-glm' ? 'live' : 'warn'}>
          {health?.mode === 'live-glm' ? 'LIVE GLM' : 'DEGRADED'}
        </StatusPill>
        <StatusPill tone="ok">{health?.model ?? 'glm-5.1'}</StatusPill>
        <button className="primary" onClick={onStart} disabled={running}>
          {running ? <Radio size={16} /> : <Play size={16} />}
          {running ? 'Running' : 'Generate Incident'}
        </button>
      </div>
    </header>
  )
}

function IncidentCard({ incident }: { incident?: Incident }) {
  if (!incident) {
    return (
      <section className="panel incident empty">
        <div className="panel__title">
          <Sparkles size={17} />
          Waiting for live incident
        </div>
        <p>
          Click Generate Incident to ask GLM-5.1 for a fresh SOC scenario. The pipeline streams
          the graph execution, checkpoint snapshots, API calls, and approval interrupts.
        </p>
      </section>
    )
  }

  return (
    <section className="panel incident">
      <div className="incident__header">
        <div>
          <span className="mono">{incident.incidentId}</span>
          <h2>{incident.incidentType}</h2>
        </div>
        <StatusPill tone={incident.severity === 'Critical' ? 'bad' : 'warn'}>
          {incident.severity}
        </StatusPill>
      </div>
      <div className="incident__grid">
        <Metric label="Priority" value={`${incident.priorityScore}/10`} tone="hot" />
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
  )
}

const nodeLabel = new Map(graphNodes.map((node) => [node.id, node.label]))

function formatNode(value?: string) {
  if (!value) return 'unknown'
  return nodeLabel.get(value) ?? value.replaceAll('_', ' ')
}

function routeText(route: AgentRoute) {
  return `${formatNode(route.from)} -> ${formatNode(route.to)}`
}

function GraphView({ run }: { run: RunState }) {
  const activeRouteIds = new Set(run.routes.map((route) => `${route.from}->${route.to}`))
  const backtrackCount = run.routes.filter((route) => route.kind === 'backtrack').length

  return (
    <section className="panel graphPanel">
      <div className="panel__title rowBetween">
        <span>
          <Workflow size={17} />
          Live LangGraph Execution
        </span>
        <StatusPill tone={backtrackCount > 0 ? 'warn' : 'ok'}>
          {backtrackCount > 0 ? `${backtrackCount} cyclic back edges` : 'cycle ready'}
        </StatusPill>
      </div>
      <div className="graphFrame">
        <div className="graph">
          <div className="graphEdges" aria-hidden="true">
            {graphEdges.map((edge) => {
              const from = graphNodes.find((node) => node.id === edge.from)
              const to = graphNodes.find((node) => node.id === edge.to)
              if (!from || !to) return null
              const active = activeRouteIds.has(`${edge.from}->${edge.to}`)
              const x1 = `${(from.order + 0.5) * (100 / 6)}%`
              const y1 = `${(from.lane + 0.5) * (100 / 3)}%`
              const x2 = `${(to.order + 0.5) * (100 / 6)}%`
              const y2 = `${(to.lane + 0.5) * (100 / 3)}%`
              return (
                <svg className={`graphEdge ${edge.kind} ${active ? 'active' : ''}`} key={edge.id}>
                  <line x1={x1} y1={y1} x2={x2} y2={y2} />
                </svg>
              )
            })}
          </div>
          {graphNodes.map((node) => {
            const status = run.statuses[node.id] ?? 'pending'
            const routeHits = run.routes.filter((route) => route.from === node.id || route.to === node.id).length
            return (
              <div
                className={`graphNode ${status} ${run.activeNode === node.id ? 'active' : ''} ${routeHits ? 'routed' : ''}`}
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
            )
          })}
        </div>
      </div>
      <RouteTrace routes={run.routes} />
    </section>
  )
}

function RouteTrace({ routes }: { routes: AgentRoute[] }) {
  return (
    <div className="routeTrace" data-testid="handoff-trace">
      <div className="routeTrace__header">
        <RefreshCw size={14} />
        <strong>Cyclic Handoff Trace</strong>
        <span>{routes.length ? `${routes.length} decisions` : 'waiting for graph'}</span>
      </div>
      {routes.length === 0 ? (
        <p className="muted">The StateGraph will list every agent handoff, including back edges to earlier agents.</p>
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
              <span>{String(index + 1).padStart(2, '0')}</span>
              <strong>{routeText(route)}</strong>
              <small>{route.kind === 'backtrack' ? 'Cyclic back edge' : route.decision}</small>
              <p>{route.reason}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function Checkpoints({
  checkpoints,
  onReplay,
}: {
  checkpoints: Checkpoint[]
  onReplay: (checkpoint: Checkpoint) => void
}) {
  return (
    <section className="panel checkpoints">
      <div className="panel__title">
        <History size={17} />
        Checkpoints & Time Travel
      </div>
      <div className="checkpointList">
        {checkpoints.length === 0 ? (
          <p className="muted">Checkpoint snapshots will appear after each node commits state.</p>
        ) : (
          checkpoints.map((item) => (
            <div
              className={`checkpoint ${item.node.includes('route') || item.node === 'time_travel_fork' ? 'cycle' : ''}`}
              data-testid="checkpoint-row"
              data-node={item.node}
              key={item.id}
            >
              <div>
                <span className="mono">{item.id}</span>
                <strong>{item.node}</strong>
                <small>{shortTime(item.timestamp)}</small>
              </div>
              <button className="ghost" onClick={() => onReplay(item)}>
                <GitBranch size={14} />
                Fork
              </button>
              <details>
                <summary>
                  <Braces size={14} /> State
                </summary>
                {isRecord(item.state.route) ? (
                  <div className="checkpointRoute">
                    <StatusPill tone={(item.state.route as unknown as AgentRoute).kind === 'backtrack' ? 'warn' : 'ok'}>
                      {(item.state.route as unknown as AgentRoute).kind === 'backtrack' ? 'Cyclic route' : 'Route'}
                    </StatusPill>
                    <strong>{routeText(item.state.route as unknown as AgentRoute)}</strong>
                    <p>{(item.state.route as unknown as AgentRoute).reason}</p>
                  </div>
                ) : null}
                {item.node === 'time_travel_fork' ? (
                  <div className="checkpointRoute">
                    <StatusPill tone="warn">Replay branch</StatusPill>
                    <strong>{String(item.state.branchName ?? 'alternate branch')}</strong>
                    <p>{String(item.state.changedDecision ?? item.state.nextAction ?? 'Forked route reviewed')}</p>
                  </div>
                ) : null}
                <pre>{JSON.stringify(item.state, null, 2)}</pre>
              </details>
            </div>
          ))
        )}
      </div>
    </section>
  )
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
              className={`timelineItem ${item.outcome} ${/cyclic|back edge|Forked/i.test(`${item.title} ${item.detail}`) ? 'cycleRoute' : ''}`}
              key={item.id}
            >
              <span>{shortTime(item.timestamp)}</span>
              <div>
                <strong>{item.title}</strong>
                {/Forked/i.test(item.title) ? <small>Cycle: checkpoint -&gt; supervisor</small> : null}
                <p>{item.detail}</p>
                {item.durationMs ? <small>{duration(item.durationMs)}</small> : null}
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  )
}

function formatPayload(value: unknown, emptyLabel = 'Not included in this SSE log') {
  if (value === undefined || value === null) return emptyLabel
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function PayloadPanel({
  title,
  value,
  emptyLabel,
}: {
  title: string
  value: unknown
  emptyLabel?: string
}) {
  return (
    <div className="payloadPanel">
      <strong>{title}</strong>
      <pre>{formatPayload(value, emptyLabel)}</pre>
    </div>
  )
}

function LlmLogDetails({ log }: { log: ApiLogEntry }) {
  const evidence = buildLlmEvidence(log)
  const promptMessages = evidence.messages?.length ? evidence.messages : evidence.prompt

  return (
    <div className="llmEvidence">
      <div className="evidenceMeta">
        <span>
          <small>Provider / model</small>
          <strong>
            {evidence.provider ?? '--'} / {evidence.model ?? '--'}
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
            {evidence.statusCode ? `${evidence.statusCode} ` : ''}
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
        <PayloadPanel title="Parsed response payload" value={evidence.parsedResponsePayload} />
      </div>
    </div>
  )
}

function ApiLog({ logs }: { logs: ApiLogEntry[] }) {
  const [filter, setFilter] = useState('all')
  const filtered = filter === 'all' ? logs : logs.filter((log) => log.type === filter)

  return (
    <section className="panel apiLog">
      <div className="panel__title rowBetween">
        <span>
          <Radio size={17} />
          API Transparency Log
        </span>
        <select value={filter} onChange={(event) => setFilter(event.target.value)}>
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
          <p className="muted">Every GLM and tool request lands here with payloads and latency.</p>
        ) : (
          filtered.map((log) => (
            <details
              className={`apiRow ${log.type} ${/route|handoff|Time Travel/i.test(`${log.callerAgent} ${log.toolName}`) ? 'cycleEvidence' : ''}`}
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
                  <PayloadPanel title="Request payload" value={log.requestPayload} />
                  <PayloadPanel title="Response payload" value={log.responsePayload} />
                </div>
              )}
            </details>
          ))
        )}
      </div>
    </section>
  )
}

function ApprovalCard({
  request,
  onDecision,
  disabled,
  statusMessage,
}: {
  request: ApprovalRequest
  onDecision: (decision: 'approve' | 'reject' | 'edit', args?: Record<string, unknown>) => void
  disabled?: boolean
  statusMessage?: string
}) {
  const [editing, setEditing] = useState(false)
  const [args, setArgs] = useState(JSON.stringify(request.toolArguments, null, 2))

  return (
    <aside className="approval">
      <div className="approval__header">
        <Pause size={18} />
        <div>
          <strong>Human approval required</strong>
          <span>{request.actionName}</span>
        </div>
        <StatusPill tone={request.severity === 'Critical' ? 'bad' : 'warn'}>{request.severity}</StatusPill>
      </div>
      <p>{request.riskJustification}</p>
      {statusMessage ? <p className="approval__status">{statusMessage}</p> : null}
      <div className="kv compact">
        <span>Target</span>
        <strong>{request.target}</strong>
        <span>Expires</span>
        <strong>{shortTime(request.expiresAt)}</strong>
      </div>
      {editing ? (
        <textarea value={args} onChange={(event) => setArgs(event.target.value)} />
      ) : (
        <pre>{JSON.stringify(request.toolArguments, null, 2)}</pre>
      )}
      <div className="approval__buttons">
        <button className="danger" disabled={disabled} onClick={() => onDecision('reject')}>
          <X size={15} />
          Reject
        </button>
        <button className="ghost" onClick={() => setEditing((value) => !value)}>
          {editing ? <ChevronDown size={15} /> : <Braces size={15} />}
          {editing ? 'Review' : 'Edit'}
        </button>
        <button
          className="primary"
          disabled={disabled}
          onClick={() => {
            if (!editing) {
              onDecision('approve')
              return
            }
            try {
              onDecision('edit', JSON.parse(args))
            } catch {
              onDecision('edit', request.toolArguments)
            }
          }}
        >
          <Check size={15} />
          {editing ? 'Edit & Approve' : 'Approve'}
        </button>
      </div>
    </aside>
  )
}

function Report({
  incident,
  report,
  run,
  toolEvidenceComplete,
  toolEvidenceCount,
}: {
  incident?: Incident
  report?: FinalReport
  run: RunState
  toolEvidenceComplete: boolean
  toolEvidenceCount: number
}) {
  const mitreMapping = safeList(report?.mitreMapping)
  const recommendations = safeList(report?.recommendations)
  const timelineItems = safeList(report?.timeline)
  const agentRouting = safeList(report?.agentRouting)
  const containmentActions = safeList(report?.containmentActions)
  const analystDecisions = safeList(report?.analystDecisions)
  const toolResultSummary = safeList(report?.toolResultSummary)
  const waitingText = (() => {
    if (run.statuses.reporting === 'running') return 'The Reporting Agent is generating the final RCA now.'
    if (run.approval && !toolEvidenceComplete) {
      return `Collecting LLM-backed enterprise tool evidence before report generation: ${toolEvidenceCount}/${toolEndpoints.length} complete.`
    }
    if (run.approval) return 'Approval is ready. The Reporting Agent will compile the RCA after analyst decision.'
    return 'The Reporting Agent compiles the final RCA after containment and notifications finish.'
  })()

  return (
    <section className="panel report" id="final-report">
      <div className="panel__title rowBetween">
        <span>
          <FileText size={17} />
          Final Incident Report
        </span>
        <span className="actions">
          <button className="ghost" onClick={() => downloadJson('soc-run-export.json', buildRunExport(run))}>
            <Download size={14} />
            JSON
          </button>
          <button className="ghost" disabled={!report} onClick={() => downloadReportPdf(incident, report)}>
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
  )
}

function ReportList({ items }: { items: string[] }) {
  if (items.length === 0) return <p className="muted">No report entries captured.</p>
  return <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul>
}

function DemoGuide({ health }: { health?: HealthResponse }) {
  return (
    <section className="panel guide">
      <div className="panel__title">
        <Sparkles size={17} />
        Demo Guide
      </div>
      <div className="guideGrid">
        <div>
          <h3>System status</h3>
          <p>
            {health?.provider ?? 'z.ai'} · {health?.model ?? 'glm-5.1'} ·{' '}
            {health?.mode === 'live-glm' ? 'live' : 'missing key'}
          </p>
          <code>{health?.endpoint ?? 'https://api.z.ai/api/coding/paas/v4'}</code>
        </div>
        <div>
          <h3>Walkthrough</h3>
          <ol>
            <li>Generate a live incident.</li>
            <li>Watch parallel subgraphs fan out.</li>
            <li>Open API logs and checkpoint state.</li>
            <li>Approve, reject, or edit containment.</li>
            <li>Fork a checkpoint and compare the branch.</li>
          </ol>
        </div>
        <div>
          <h3>LangGraph proof points</h3>
          <p>
            Real StateGraph orchestration, cyclic back edges, supervisor re-entry, specialist
            subgraphs, Send fan-out, interrupt/resume, checkpoint IDs, time travel, map-reduce,
            streaming, and audit logging.
          </p>
        </div>
      </div>
    </section>
  )
}

function App() {
  const [health, setHealth] = useState<HealthResponse>()
  const [run, setRun] = useState<RunState>(initialRun)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string>()
  const [toolFanoutState, setToolFanoutState] = useState<'idle' | 'running' | 'complete'>('idle')
  const fanoutRunRef = useRef(0)

  useEffect(() => {
    fetch('/api/health')
      .then((response) => response.json())
      .then(setHealth)
      .catch(() => {
        setHealth({
          service: 'soc-ai-agent-demo',
          status: 'degraded',
          mode: 'missing-key',
          provider: 'z.ai',
          model: 'glm-5.1',
          endpoint: 'unavailable',
          checkedAt: new Date().toISOString(),
          capabilities: {},
          models: ['glm-5.1'],
        })
      })
  }, [])

  const toolCount = useMemo(() => run.apiLogs.filter((log) => log.type === 'tool').length, [run.apiLogs])
  const toolEvidenceComplete = toolFanoutState === 'complete' && toolCount >= toolEndpoints.length
  const toolMetric = useMemo(() => {
    const denominator = Math.max(toolEndpoints.length, toolCount)
    return `${toolCount}/${denominator}`
  }, [toolCount])
  const tokenCount = useMemo(
    () => run.apiLogs.reduce((sum, log) => sum + (log.tokenCount ?? 0), 0),
    [run.apiLogs],
  )

  useEffect(() => {
    if (!run.report) return
    document.getElementById('final-report')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [run.report])

  const handleEvent = (item: SseEvent) => {
    if (item.event === 'error') {
      const data = item.data as { message: string }
      setError(data.message)
    }
    if (item.event === 'incident') {
      const incident = item.data as Incident
      const fanoutId = fanoutRunRef.current
      setToolFanoutState('running')
      void runEnterpriseToolFanout(incident, (logs) => {
        setRun((current) => {
          if (fanoutId !== fanoutRunRef.current) return current
          return { ...current, apiLogs: [...current.apiLogs, ...logs] }
        })
      }).finally(() => {
        if (fanoutId === fanoutRunRef.current) setToolFanoutState('complete')
      })
    }
    setRun((current) => applyRunEvent(current, item))
  }

  const startRun = async () => {
    fanoutRunRef.current += 1
    setRunning(true)
    setError(undefined)
    setToolFanoutState('idle')
    setRun(initialRun)
    try {
      const response = await fetch('/api/agent-run', { method: 'POST' })
      await consumeSse(response, handleEvent)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Agent run failed')
    } finally {
      setRunning(false)
    }
  }

  const decide = async (
    decision: 'approve' | 'reject' | 'edit',
    editedArguments?: Record<string, unknown>,
  ) => {
    if (!run.approval) return
    const approval = run.approval
    if (!toolEvidenceComplete) {
      setError(`Final report is waiting for all ${toolEndpoints.length} LLM-backed tool calls to finish.`)
      return
    }
    setRunning(true)
    setError(undefined)
    const payload = {
      decision,
      editedArguments,
      approval,
      checkpoints: run.checkpoints,
      routes: run.routes,
      timeline: run.timeline,
      apiLogs: run.apiLogs,
      streamText: run.streamText,
    }
    const humanLog: ApiLogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      callerAgent: 'SOC Analyst',
      toolName: 'Human Approval',
      method: 'COMMAND',
      endpointUrl: 'Command(resume=...)',
      requestPayload: payload,
      responsePayload: { decision },
      latencyMs: 0,
      status: 'ok',
      type: 'human',
    }
    setRun((current) => ({
      ...current,
      approval: undefined,
      apiLogs: [...current.apiLogs, humanLog],
      statuses: { ...current.statuses, containment: decision === 'reject' ? 'failed' : 'running' },
    }))
    try {
      let resumeFailed = false
      const response = await fetch('/api/resume-run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      })
      await consumeSse(response, (item) => {
        if (item.event === 'error') resumeFailed = true
        handleEvent(item)
      })
      if (resumeFailed) {
        setRun((current) => ({
          ...current,
          approval,
          statuses: { ...current.statuses, containment: 'paused' },
        }))
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Resume failed')
      setRun((current) => ({
        ...current,
        approval,
        statuses: { ...current.statuses, containment: 'paused' },
      }))
    } finally {
      setRunning(false)
    }
  }

  const replay = async (checkpoint: Checkpoint) => {
    if (!run.incident) return
    setRunning(true)
    setError(undefined)
    try {
      const response = await fetch('/api/replay-run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ checkpoint, incident: run.incident, threadId: run.threadId }),
      })
      await consumeSse(response, handleEvent)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Replay failed')
    } finally {
      setRunning(false)
    }
  }

  return (
    <main>
      <Header health={health} running={running} onStart={startRun} />
      {error ? (
        <div className="errorBanner">
          <AlertTriangle size={16} />
          {error}
        </div>
      ) : null}
      <section className="heroBand">
        <div>
          <p className="mono">Thread {run.threadId || 'not started'} · Run {run.runId || 'idle'}</p>
          <h2>One-button SOC investigation with visible graph mechanics.</h2>
        </div>
        <div className="metricsRow">
          <Metric label="Checkpoints" value={`${run.checkpoints.length}`} tone="cool" />
          <Metric label="Tool calls" value={toolMetric} />
          <Metric label="Tokens" value={`${tokenCount}`} tone="ok" />
          <Metric label="MTTR" value={run.mttrMs ? duration(run.mttrMs) : '--'} tone="hot" />
        </div>
      </section>
      <div className="layout">
        <div className="mainColumn">
          <IncidentCard incident={run.incident} />
          <GraphView run={run} />
          <Report
            incident={run.incident}
            report={run.report}
            run={run}
            toolEvidenceComplete={toolEvidenceComplete}
            toolEvidenceCount={toolCount}
          />
        </div>
        <div className="sideColumn">
          <DemoGuide health={health} />
          <Checkpoints checkpoints={run.checkpoints} onReplay={replay} />
        </div>
      </div>
      <div className="layout lower">
        <Timeline events={run.timeline} />
        <ApiLog logs={run.apiLogs} />
      </div>
      {run.streamText ? (
        <section className="panel stream">
          <div className="panel__title">
            <Radio size={17} />
            GLM Streaming Output
          </div>
          <pre>{run.streamText}</pre>
        </section>
      ) : null}
      {run.approval ? (
        <ApprovalCard
          request={run.approval}
          onDecision={decide}
          disabled={running || !toolEvidenceComplete}
          statusMessage={
            toolEvidenceComplete
              ? 'All enterprise tool evidence is captured. Analyst decision will generate the final report.'
              : `Waiting for LLM-backed tool evidence: ${toolCount}/${toolEndpoints.length} complete.`
          }
        />
      ) : null}
    </main>
  )
}

function safeList(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item))
  if (typeof value === 'string' && value.trim()) return [value]
  return []
}

export default App
