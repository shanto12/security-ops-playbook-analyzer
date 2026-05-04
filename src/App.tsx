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
  ShieldAlert,
  Sparkles,
  Workflow,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { graphNodes, toolEndpoints } from './data/graph'
import { buildRunExport, downloadJson, downloadReportPdf } from './lib/export'
import { consumeSse } from './lib/sse'
import type {
  ApiLogEntry,
  ApprovalRequest,
  Checkpoint,
  FinalReport,
  HealthResponse,
  Incident,
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
    case 'checkpoint':
      return { ...current, checkpoints: [...current.checkpoints, item.data as Checkpoint] }
    case 'api_call':
      return { ...current, apiLogs: [...current.apiLogs, item.data as ApiLogEntry] }
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

function GraphView({ run }: { run: RunState }) {
  return (
    <section className="panel graphPanel">
      <div className="panel__title">
        <Workflow size={17} />
        Live LangGraph Execution
      </div>
      <div className="graph">
        {graphNodes.map((node) => {
          const status = run.statuses[node.id] ?? 'pending'
          return (
            <div
              className={`graphNode ${status} ${run.activeNode === node.id ? 'active' : ''}`}
              key={node.id}
              style={{
                gridColumn: node.order + 1,
                gridRow: node.lane + 1,
              }}
              title={node.description}
            >
              <span className="graphNode__capability">{node.capability}</span>
              <strong>{node.label}</strong>
              <small>{statusLabel[status]}</small>
            </div>
          )
        })}
      </div>
    </section>
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
            <div className="checkpoint" key={item.id}>
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
            <div className={`timelineItem ${item.outcome}`} key={item.id}>
              <span>{shortTime(item.timestamp)}</span>
              <div>
                <strong>{item.title}</strong>
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
          <option value="error">Errors</option>
        </select>
      </div>
      <div className="apiRows">
        {filtered.length === 0 ? (
          <p className="muted">Every GLM and tool request lands here with payloads and latency.</p>
        ) : (
          filtered.map((log) => (
            <details className={`apiRow ${log.type}`} key={log.id}>
              <summary>
                <span>{shortTime(log.timestamp)}</span>
                <strong>{log.toolName}</strong>
                <small>{log.callerAgent}</small>
                <em>{log.latencyMs}ms</em>
                {log.tokenCount ? <b>{log.tokenCount} tok</b> : null}
              </summary>
              <div className="apiPayloads">
                <pre>{JSON.stringify(log.requestPayload, null, 2)}</pre>
                <pre>{JSON.stringify(log.responsePayload, null, 2)}</pre>
              </div>
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
}: {
  request: ApprovalRequest
  onDecision: (decision: 'approve' | 'reject' | 'edit', args?: Record<string, unknown>) => void
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
        <button className="danger" onClick={() => onDecision('reject')}>
          <X size={15} />
          Reject
        </button>
        <button className="ghost" onClick={() => setEditing((value) => !value)}>
          {editing ? <ChevronDown size={15} /> : <Braces size={15} />}
          {editing ? 'Review' : 'Edit'}
        </button>
        <button
          className="primary"
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
}: {
  incident?: Incident
  report?: FinalReport
  run: RunState
}) {
  return (
    <section className="panel report">
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
        <p className="muted">The Reporting Agent compiles the final RCA after containment and notifications finish.</p>
      ) : (
        <div className="reportBody">
          <h3>Executive Summary</h3>
          <p>{report.executiveSummary}</p>
          <h3>Root Cause</h3>
          <p>{report.rootCause}</p>
          <h3>MITRE Mapping</h3>
          <ul>{report.mitreMapping.map((item) => <li key={item}>{item}</li>)}</ul>
          <h3>Recommendations</h3>
          <ul>{report.recommendations.map((item) => <li key={item}>{item}</li>)}</ul>
        </div>
      )}
    </section>
  )
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
            StateGraph, supervisor routing, specialist subgraphs, Send fan-out, interrupt/resume,
            SQLite-style checkpoint IDs, time travel, map-reduce, streaming, and audit logging.
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
  const tokenCount = useMemo(
    () => run.apiLogs.reduce((sum, log) => sum + (log.tokenCount ?? 0), 0),
    [run.apiLogs],
  )

  const handleEvent = (item: SseEvent) => {
    if (item.event === 'error') {
      const data = item.data as { message: string }
      setError(data.message)
    }
    setRun((current) => applyRunEvent(current, item))
  }

  const startRun = async () => {
    setRunning(true)
    setError(undefined)
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
    setRunning(true)
    setError(undefined)
    const payload = {
      decision,
      editedArguments,
      approval: run.approval,
      checkpoints: run.checkpoints,
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
      const response = await fetch('/api/resume-run', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      })
      await consumeSse(response, handleEvent)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Resume failed')
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
          <Metric label="Tool calls" value={`${toolCount}/${toolEndpoints.length}`} />
          <Metric label="Tokens" value={`${tokenCount}`} tone="ok" />
          <Metric label="MTTR" value={run.mttrMs ? duration(run.mttrMs) : '--'} tone="hot" />
        </div>
      </section>
      <div className="layout">
        <div className="mainColumn">
          <IncidentCard incident={run.incident} />
          <GraphView run={run} />
          <Report incident={run.incident} report={run.report} run={run} />
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
      {run.approval ? <ApprovalCard request={run.approval} onDecision={decide} /> : null}
    </main>
  )
}

export default App
