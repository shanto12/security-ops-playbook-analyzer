export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'
export type AgentStatus = 'pending' | 'running' | 'complete' | 'failed' | 'paused'
export type ApiLogType = 'llm' | 'tool' | 'human' | 'routing' | 'error'
export type ApiLogStatus = 'ok' | 'error' | string

export interface LlmMessage {
  role?: string
  content?: unknown
  [key: string]: unknown
}

export interface LlmEvidence {
  provider?: string
  model?: string
  endpoint?: string
  method?: string
  latencyMs?: number
  status?: ApiLogStatus
  statusCode?: number
  tokenCount?: number
  prompt?: unknown
  messages?: LlmMessage[]
  requestPayload?: unknown
  rawResponsePayload?: unknown
  parsedResponsePayload?: unknown
}

export interface HealthResponse {
  service: string
  status: 'ok' | 'degraded'
  mode: 'live-glm' | 'missing-key'
  provider: string
  model: string
  toolModel?: string
  orchestrationProvider?: string
  fireworksModel?: string | null
  endpoint: string
  checkedAt: string
  capabilities: Record<string, boolean>
  models: string[]
}

export interface Incident {
  incidentId: string
  timestamp: string
  severity: Severity
  priorityScore: number
  incidentType: string
  affectedUser: string
  affectedHost: string
  affectedIp: string
  affectedDepartment: string
  mitreTactic: string
  mitreTechnique: string
  initialAlertSource: 'SIEM' | 'EDR' | 'NDR' | 'UEBA'
  iocs: {
    ip: string
    hash: string
    domain: string
    url: string
  }
  rawLogSnippet: string
}

export interface GraphNode {
  id: string
  label: string
  lane: number
  order: number
  description: string
  capability: string
}

export interface GraphEdge {
  id: string
  from: string
  to: string
  label: string
  kind: 'forward' | 'parallel' | 'interrupt' | 'resume' | 'backtrack'
  cycleId?: string
}

export interface AgentRoute {
  id: string
  runId?: string
  threadId?: string
  cycleId: string
  from: string
  to: string
  reason: string
  decision: string
  kind: GraphEdge['kind']
  iteration: number
  checkpointId?: string
  timestamp: string
  confidence?: number
  stateDelta?: Record<string, unknown>
}

export interface Checkpoint {
  id: string
  timestamp: string
  node: string
  state: Record<string, unknown>
}

export interface TimelineEvent {
  id: string
  timestamp: string
  title: string
  detail: string
  outcome: 'info' | 'success' | 'warning' | 'error'
  durationMs?: number
}

export interface ApiLogEntry {
  id: string
  timestamp: string
  callerAgent: string
  toolName: string
  method: string
  endpointUrl: string
  provider?: string
  model?: string
  requestPayload: unknown
  responsePayload: unknown
  rawResponsePayload?: unknown
  parsedResponsePayload?: unknown
  prompt?: unknown
  messages?: LlmMessage[]
  statusCode?: number
  statusText?: string
  latencyMs: number
  tokenCount?: number
  status: ApiLogStatus
  type: ApiLogType
  llmEvidence?: LlmEvidence
}

export interface ApprovalRequest {
  runId: string
  actionName: string
  target: string
  toolArguments: Record<string, unknown>
  riskJustification: string
  severity: Severity
  expiresAt: string
  incident: Incident
  stateSnapshot: Record<string, unknown>
}

export interface FinalReport {
  executiveSummary: string
  rootCause: string
  mitreMapping: string[]
  timeline: string[]
  agentRouting: string[]
  containmentActions: string[]
  recommendations: string[]
  analystDecisions: string[]
  toolResultSummary: string[]
}

export interface RunState {
  runId: string
  threadId: string
  incident?: Incident
  activeNode?: string
  statuses: Record<string, AgentStatus>
  timeline: TimelineEvent[]
  apiLogs: ApiLogEntry[]
  routes: AgentRoute[]
  checkpoints: Checkpoint[]
  approval?: ApprovalRequest
  report?: FinalReport
  streamText: string
  startedAt?: string
  completedAt?: string
  mttrMs?: number
}

export interface SseEvent<T = unknown> {
  event: string
  data: T
}

export type RunEvent =
  | { event: 'start'; data: { runId: string; threadId: string; startedAt: string } }
  | { event: 'node_start'; data: { node: string; timestamp: string } }
  | { event: 'node_complete'; data: { node: string; timestamp: string; durationMs: number; summary?: string } }
  | { event: 'node_failed'; data: { node: string; timestamp: string; error: string } }
  | { event: 'checkpoint'; data: Checkpoint }
  | { event: 'timeline'; data: TimelineEvent }
  | { event: 'agent_route'; data: AgentRoute }
  | { event: 'api_call'; data: ApiLogEntry }
  | { event: 'delta'; data: { node: string; content: string } }
  | { event: 'incident'; data: Incident }
  | {
      event: 'tool_fanout_required'
      data: {
        incident: Incident
        state: Record<string, unknown>
        tools: Array<{ name: string; endpoint: string; agent: string }>
        concurrency: number
        evidenceRequirement: string
      }
    }
  | { event: 'approval_required'; data: ApprovalRequest }
  | { event: 'report'; data: FinalReport }
  | { event: 'complete'; data: { completedAt: string; mttrMs: number } }
  | { event: 'error'; data: { message: string; node?: string } }
  | { event: 'done'; data: Record<string, never> }
