import { afterEach, describe, expect, it, vi } from 'vitest'
import agentRun from '../netlify/functions-src/agent-run.mts'
import replayRun from '../netlify/functions-src/replay-run.mts'
import resumeRun from '../netlify/functions-src/resume-run.mts'
import toolGateway from '../netlify/functions-src/tool-gateway.mts'
import { consumeSse } from '../src/lib/sse'
import type { SseEvent } from '../src/lib/types'

type LlmLog = {
  type: string
  status: string
  requestPayload?: Record<string, unknown>
  responsePayload?: unknown
  tokenCount?: number
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

    expect.soft(llmLogs).toHaveLength(1)
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
    vi.stubEnv('FIREWORKS_API_KEY', 'test-key')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        providerResponse(
          {
            executiveSummary: 'Synthetic report generated by provider.',
            rootCause: 'Credential access test root cause.',
            mitreMapping: ['Credential Access', 'T1003'],
            timeline: ['Incident created', 'Containment approved'],
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
    expect.soft(events.at(-1)?.event).toBe('done')
    expectFullLlmEvidence(llmLogs[0])
  })

  it('returns full LLM audit evidence from direct enterprise tool endpoints', async () => {
    vi.stubEnv('GLM_API_KEY', 'test-key')
    vi.stubGlobal('fetch', vi.fn(async () => providerResponse({ issueKey: 'SEC-1234', status: 'Created' }, 222)))

    const response = await toolGateway(
      new Request('https://example.test/api/jira/issue', {
        method: 'POST',
        body: JSON.stringify({ incidentId: 'SOC-TEST-001', indicator: 'stage.example' }),
      }),
    )
    const body = await response.json()

    expect.soft(response.status).toBe(200)
    expect.soft(body.llmAudit).toEqual(expect.any(Object))
    expectFullLlmEvidence({
      type: 'llm',
      status: body.llmAudit.status,
      requestPayload: body.llmAudit.requestPayload,
      responsePayload: body.llmAudit.parsedResponsePayload,
      tokenCount: body.llmAudit.tokenCount,
    })
  })
})
