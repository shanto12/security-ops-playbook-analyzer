import { afterEach, describe, expect, it, vi } from 'vitest'
import agentRun from '../netlify/functions-src/agent-run.mts'
import replayRun from '../netlify/functions-src/replay-run.mts'
import resumeRun from '../netlify/functions-src/resume-run.mts'
import toolGateway from '../netlify/functions-src/tool-gateway.mts'
import { toolEndpoints } from '../src/data/graph'
import { consumeSse } from '../src/lib/sse'
import type { SseEvent } from '../src/lib/types'

type LlmLog = {
  type: string
  status: string
  requestPayload?: Record<string, unknown>
  responsePayload?: Record<string, unknown>
  tokenCount?: number
}

type ReportEvent = {
  mitreMapping?: string[]
  timeline?: string[]
  agentRouting?: string[]
  containmentActions?: string[]
  recommendations?: string[]
  analystDecisions?: string[]
  toolResultSummary?: string[]
}

const providerResponse = (content: unknown, totalTokens = 321) =>
  Response.json({
    id: 'chatcmpl-test',
    model: 'glm-5.1',
    choices: [{ message: { role: 'assistant', content: JSON.stringify(content) } }],
    usage: {
      prompt_tokens: 123,
      completion_tokens: totalTokens - 123,
      total_tokens: totalTokens,
    },
  })

const runPlan = {
  i: {
    incidentId: 'SOC-TEST-001',
    timestamp: '2026-05-03T12:00:00.000Z',
    severity: 'High',
    priorityScore: 8,
    incidentType: 'credential access',
    affectedUser: 'analyst@example.com',
    affectedHost: 'WS-TEST-001',
    affectedIp: '10.10.10.10',
    affectedDepartment: 'Finance',
    mitreTactic: 'Credential Access',
    mitreTechnique: 'T1003 OS Credential Dumping',
    initialAlertSource: 'EDR',
    iocs: {
      ip: '10.10.10.10',
      hash: 'a'.repeat(64),
      domain: 'stage.example',
      url: 'https://stage.example/payload',
    },
    rawLogSnippet: 'EDR alert for test host',
  },
  s: {
    route: 'containment',
    rationale: 'High confidence endpoint and identity correlation.',
    agents: ['Triage', 'Endpoint'],
    conf: 0.91,
  },
  t: {
    class: 'Confirmed malicious activity',
    dedupe: 'new',
    risk: 88,
    findings: ['Test IOC correlated with affected host'],
  },
  v: [
    {
      name: 'VirusTotal',
      endpoint: '/api/virustotal/lookup',
      responsePayload: { verdict: 'malicious', evidence: 'test IOC seen by vendors' },
      tokenCount: 11,
    },
  ],
  a: {
    actionName: 'isolate_host',
    target: 'WS-TEST-001',
    toolArguments: { host: 'WS-TEST-001', durationMinutes: 45 },
    riskJustification: 'Containment prevents lateral movement.',
  },
  routingPlan: [
    {
      from: 'supervisor',
      to: 'triage',
      kind: 'forward',
      decision: 'route_initial_triage',
      reason: 'Supervisor starts triage.',
      confidence: 0.8,
    },
    {
      from: 'triage',
      to: 'enrichment',
      kind: 'parallel',
      decision: 'expand_iocs',
      reason: 'Triage expands IOC context.',
      confidence: 0.82,
    },
    {
      from: 'enrichment',
      to: 'identity',
      kind: 'forward',
      decision: 'check_identity',
      reason: 'Enrichment pivots to identity.',
      confidence: 0.83,
    },
    {
      from: 'identity',
      to: 'endpoint',
      kind: 'forward',
      decision: 'check_endpoint',
      reason: 'Identity pivots to endpoint.',
      confidence: 0.84,
    },
    {
      from: 'endpoint',
      to: 'log_analysis',
      kind: 'forward',
      decision: 'reduce_logs',
      reason: 'Endpoint requests log analysis.',
      confidence: 0.85,
    },
    {
      from: 'log_analysis',
      to: 'enrichment',
      kind: 'backtrack',
      decision: 'loop_back_for_ioc_pivot',
      reason: 'Log analysis found a new IOC.',
      confidence: 0.86,
    },
    {
      from: 'enrichment',
      to: 'identity',
      kind: 'forward',
      decision: 'recheck_identity',
      reason: 'Enrichment updates identity scope.',
      confidence: 0.87,
    },
    {
      from: 'identity',
      to: 'endpoint',
      kind: 'forward',
      decision: 'recheck_endpoint',
      reason: 'Identity returns to endpoint.',
      confidence: 0.88,
    },
    {
      from: 'endpoint',
      to: 'log_analysis',
      kind: 'forward',
      decision: 'second_log_pass',
      reason: 'Endpoint asks for second log pass.',
      confidence: 0.89,
    },
    {
      from: 'log_analysis',
      to: 'threat_intel',
      kind: 'forward',
      decision: 'map_ttp',
      reason: 'Logs are ready for threat intel.',
      confidence: 0.9,
    },
    {
      from: 'threat_intel',
      to: 'supervisor',
      kind: 'backtrack',
      decision: 'return_to_supervisor',
      reason: 'Threat intel returns to supervisor.',
      confidence: 0.91,
    },
    {
      from: 'supervisor',
      to: 'containment',
      kind: 'interrupt',
      decision: 'pause_for_human_approval',
      reason: 'Supervisor pauses for containment approval.',
      confidence: 0.92,
    },
  ],
}

function containsPromptOrMessages(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some((item) => containsPromptOrMessages(item))

  const record = value as Record<string, unknown>
  const messages = record.messages
  if (Array.isArray(messages) && messages.length > 0) return true

  const prompt = record.prompt
  if (typeof prompt === 'string' && prompt.trim().length > 0) return true

  return Object.values(record).some((item) => containsPromptOrMessages(item))
}

function expectFullLlmEvidence(log: LlmLog) {
  expect.soft(log.type).toBe('llm')
  expect.soft(log.status).toBe('ok')
  expect.soft(log.responsePayload).toEqual(expect.any(Object))
  expect.soft(log.tokenCount).toEqual(expect.any(Number))
  expect.soft(log.tokenCount).toBeGreaterThan(0)
  expect.soft(containsPromptOrMessages(log.requestPayload)).toBe(true)
}

function expectCompleteReport(report: ReportEvent | undefined) {
  expect.soft(report?.mitreMapping?.length).toBeGreaterThanOrEqual(2)
  expect.soft(report?.timeline?.length).toBeGreaterThanOrEqual(4)
  expect.soft(report?.agentRouting?.some((item) => /backtrack|supervisor/i.test(item))).toBe(true)
  expect.soft(report?.containmentActions?.length).toBeGreaterThanOrEqual(2)
  expect.soft(report?.recommendations?.length).toBeGreaterThanOrEqual(4)
  expect.soft(report?.analystDecisions?.some((item) => /approve.*isolate_host/i.test(item))).toBe(true)
  expect.soft(report?.toolResultSummary?.length).toBeGreaterThanOrEqual(2)
}

async function collectSse(response: Response) {
  const events: SseEvent[] = []
  await consumeSse(response, (event) => events.push(event))
  return events
}

describe('LLM API log evidence', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.unstubAllEnvs()
  })

  it('logs full LLM request and response evidence before agent-run reaches terminal HITL SSE events', async () => {
    vi.stubEnv('GLM_API_KEY', 'test-key')
    vi.stubEnv('GLM_TOOL_MODEL', 'glm-5-turbo')
    vi.stubEnv('FIREWORKS_API_KEY', '')
    vi.stubGlobal('fetch', vi.fn(async () => providerResponse(runPlan, 456)))

    const response = await agentRun(new Request('https://example.test/api/agent-run', { method: 'POST' }))
    const events = await collectSse(response)
    const llmLogs = events
      .filter((event) => event.event === 'api_call')
      .map((event) => event.data as LlmLog)
      .filter((log) => log.type === 'llm')
    const toolLogs = events
      .filter((event) => event.event === 'api_call')
      .map((event) => event.data as LlmLog)
      .filter((log) => log.type === 'tool')

    const fanout = events.find((event) => event.event === 'tool_fanout_required')
    const routes = events
      .filter((event) => event.event === 'agent_route')
      .map((event) => event.data as { kind?: string; from?: string; to?: string; checkpointId?: string })
    const routingLogs = events
      .filter((event) => event.event === 'api_call')
      .map((event) => event.data as LlmLog)
      .filter((log) => log.type === 'routing')
    const routeCheckpoints = events
      .filter((event) => event.event === 'checkpoint')
      .map((event) => event.data as { state?: Record<string, unknown> })
      .filter((checkpoint) => checkpoint.state?.route)

    expect.soft(llmLogs).toHaveLength(1)
    expect.soft(toolLogs).toHaveLength(0)
    expect.soft((fanout?.data as { tools?: unknown[] } | undefined)?.tools).toHaveLength(10)
    expect.soft(routes.length).toBeGreaterThanOrEqual(8)
    expect.soft(routes.some((route) => route.kind === 'backtrack' && route.to === 'supervisor')).toBe(true)
    expect.soft(routes.every((route) => Boolean(route.checkpointId))).toBe(true)
    expect.soft(routingLogs.length).toBeGreaterThanOrEqual(routes.length)
    expect.soft(routeCheckpoints.length).toBeGreaterThanOrEqual(routes.length)
    expect.soft(events.some((event) => event.event === 'approval_required')).toBe(true)
    expect.soft(events.at(-1)?.event).toBe('done')
    expectFullLlmEvidence(llmLogs[0])
  })

  it('logs full LLM request and response evidence before replay-run sends done', async () => {
    vi.stubEnv('GLM_API_KEY', 'test-key')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        providerResponse(
          {
            branchName: 'alternate-containment',
            changedDecision: 'Escalate identity review before host isolation',
            reason: 'Replay found stronger identity signal.',
            nextAction: 'Disable risky sessions',
            expectedImpact: 'Lower disruption while preserving containment.',
          },
          234,
        ),
      ),
    )

    const response = await replayRun(
      new Request('https://example.test/api/replay-run', {
        method: 'POST',
        body: JSON.stringify({
          checkpoint: { id: 'ckpt-test', node: 'supervisor' },
          incident: runPlan.i,
        }),
      }),
    )
    const events = await collectSse(response)
    const llmLogs = events
      .filter((event) => event.event === 'api_call')
      .map((event) => event.data as LlmLog)
      .filter((log) => log.type === 'llm')

    expect.soft(llmLogs).toHaveLength(1)
    expect.soft(events.at(-1)?.event).toBe('done')
    expectFullLlmEvidence(llmLogs[0])
  })

  it('logs full LLM request and response evidence during resume-run reporting', async () => {
    vi.stubEnv('GLM_API_KEY', 'test-key')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        providerResponse(
          {
            executiveSummary: 'Synthetic report generated by provider.',
            rootCause: 'Credential access test root cause.',
            mitreMapping: ['Credential Access', 'T1003'],
            timeline: ['Incident created', 'Containment approved'],
            agentRouting: ['Log Analysis -> Enrichment (backtrack)', 'Threat Intel -> Supervisor (backtrack)'],
            containmentActions: ['Host isolation queued'],
            recommendations: ['Rotate credentials'],
            analystDecisions: ['approve isolate_host'],
            toolResultSummary: ['Ticketing complete'],
          },
          345,
        ),
      ),
    )

    const response = await resumeRun(
      new Request('https://example.test/api/resume-run', {
        method: 'POST',
        body: JSON.stringify({
          decision: 'approve',
          approval: {
            runId: 'run-test',
            actionName: 'isolate_host',
            target: 'WS-TEST-001',
            toolArguments: { host: 'WS-TEST-001' },
            riskJustification: 'Test approval.',
            severity: 'High',
            incident: runPlan.i,
          },
          routes: runPlan.routingPlan,
        }),
      }),
    )
    const events = await collectSse(response)
    const llmLogs = events
      .filter((event) => event.event === 'api_call')
      .map((event) => event.data as LlmLog)
      .filter((log) => log.type === 'llm')

    expect.soft(llmLogs).toHaveLength(1)
    expect.soft(events.some((event) => event.event === 'report')).toBe(true)
    const report = events.find((event) => event.event === 'report')?.data as ReportEvent | undefined
    expectCompleteReport(report)
    expect.soft(events.at(-1)?.event).toBe('done')
    expectFullLlmEvidence(llmLogs[0])
  })

  it('repairs sparse report arrays from run evidence while preserving raw LLM audit output', async () => {
    vi.stubEnv('GLM_API_KEY', 'test-key')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        providerResponse(
          {
            executiveSummary: 'Sparse provider report.',
            rootCause: 'Sparse provider root cause.',
            mitreMapping: [],
            timeline: [],
            agentRouting: [],
            containmentActions: [],
            recommendations: [],
            analystDecisions: [],
            toolResultSummary: [],
          },
          345,
        ),
      ),
    )

    const response = await resumeRun(
      new Request('https://example.test/api/resume-run', {
        method: 'POST',
        body: JSON.stringify({
          decision: 'approve',
          approval: {
            runId: 'run-test',
            actionName: 'isolate_host',
            target: 'WS-TEST-001',
            toolArguments: { host: 'WS-TEST-001' },
            riskJustification: 'Test approval.',
            severity: 'High',
            incident: runPlan.i,
          },
          routes: runPlan.routingPlan,
          timeline: [
            { title: 'Run started', detail: 'Supervisor accepted test incident.', outcome: 'success' },
            { title: 'Parallel superstep started', detail: 'Tool fanout started.', outcome: 'success' },
            { title: 'Containment paused', detail: 'HITL card shown.', outcome: 'warning' },
            { title: 'Command(resume=...) received', detail: 'Analyst decision: approve', outcome: 'success' },
          ],
          apiLogs: [
            {
              type: 'tool',
              toolName: 'VirusTotal',
              callerAgent: 'Enrichment Agent',
              endpointUrl: '/api/virustotal/lookup',
              status: 'ok',
              latencyMs: 1234,
              tokenCount: 456,
              responsePayload: { verdict: 'malicious' },
            },
            {
              type: 'tool',
              toolName: 'SIEM',
              callerAgent: 'Log Analysis Agent',
              endpointUrl: '/api/siem/search',
              status: 'ok',
              latencyMs: 2345,
              tokenCount: 567,
              responsePayload: { events: 12 },
            },
          ],
        }),
      }),
    )
    const events = await collectSse(response)
    const llmLog = events
      .filter((event) => event.event === 'api_call')
      .map((event) => event.data as LlmLog)
      .find((log) => log.type === 'llm')
    const report = events.find((event) => event.event === 'report')?.data as ReportEvent | undefined

    expectCompleteReport(report)
    expect.soft(llmLog?.responsePayload?.normalizedOutput).toMatchObject({
      mitreMapping: [],
      timeline: [],
      containmentActions: [],
      recommendations: [],
      analystDecisions: [],
      toolResultSummary: [],
    })
    expectFullLlmEvidence(llmLog as LlmLog)
  })

  it('returns full LLM audit evidence from all direct enterprise tool endpoints', async () => {
    vi.stubEnv('GLM_API_KEY', 'test-key')
    vi.stubGlobal('fetch', vi.fn(async () => providerResponse({ issueKey: 'SEC-1234', status: 'Created' }, 222)))

    for (const tool of toolEndpoints) {
      const response = await toolGateway(
        new Request(`https://example.test${tool.endpoint}`, {
          method: 'POST',
          body: JSON.stringify({ incidentId: 'SOC-TEST-001', indicator: 'stage.example' }),
        }),
      )
      const body = await response.json()

      expect.soft(response.status).toBe(200)
      expect.soft(body.tool).toBe(tool.name)
      expect.soft(body.llmAudit).toEqual(expect.any(Object))
      expectFullLlmEvidence({
        type: 'llm',
        status: body.llmAudit.status,
        requestPayload: body.llmAudit.requestPayload,
        responsePayload: body.llmAudit.parsedResponsePayload,
        tokenCount: body.llmAudit.tokenCount,
      })
    }
  })
})
