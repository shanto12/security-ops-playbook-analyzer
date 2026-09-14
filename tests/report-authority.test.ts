import { afterEach, describe, expect, it, vi } from 'vitest'
import resumeRun from '../netlify/functions-src/resume-run.mts'
import { consumeSse } from '../src/lib/sse'
import type { SseEvent } from '../src/lib/types'

const originalHost = 'ORIGINAL-HOST-DO-NOT-EXECUTE'
const editedHost = 'EDITED-HOST-ONLY'
const misleadingModelReport = {
  executiveSummary: 'Synthetic investigation narrative from the model.',
  rootCause: 'Synthetic root cause requiring review.',
  containmentActions: [
    `Executed host isolation on ${originalHost} for 45 minutes.`,
    `Disabled the account and firewall access on ${originalHost}.`,
  ],
  analystDecisions: [`approve isolate_host for ${originalHost} for 45 minutes; disable_user true.`],
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

async function runWithContradictoryModel(decision: string, editedArguments?: Record<string, unknown>) {
  vi.stubEnv('AI_PROVIDER', 'deepseek')
  vi.stubEnv('DEEPSEEK_API_KEY', 'unit-test-only')
  const providerBodies: any[] = []
  const fetchMock = vi.fn(async (_url, options) => {
    providerBodies.push(JSON.parse(options.body))
    return Response.json({
      choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(misleadingModelReport) } }],
      usage: { prompt_tokens: 80, completion_tokens: 40, total_tokens: 120 },
    })
  })
  vi.stubGlobal('fetch', fetchMock)
  const response = await resumeRun(new Request('https://example.test/api/resume-run', {
    method: 'POST',
    body: JSON.stringify({
      decision,
      editedArguments,
      approval: {
        runId: 'authority-test',
        actionName: 'isolate_host',
        target: originalHost,
        toolArguments: { host: originalHost, durationMinutes: 45, disable_user: true },
        incident: { incidentId: 'SOC-AUTHORITY-TEST', affectedHost: originalHost, affectedUser: 'synthetic-user@example.test' },
      },
    }),
  }))
  const events: SseEvent[] = []
  await consumeSse(response, event => events.push(event))
  expect(events.some(event => event.event === 'error')).toBe(false)
  expect(events.some(event => event.event === 'complete')).toBe(true)
  expect(fetchMock).toHaveBeenCalledTimes(1)
  const report = events.find(event => event.event === 'report')?.data as any
  const checkpoint = events.find(event => event.event === 'checkpoint' && (event.data as any).node === 'containment_resume')?.data as any
  const audit = events.find(event => event.event === 'api_call' && (event.data as any).type === 'llm')?.data as any
  // Preserve the original bad model answer for audit instead of rewriting history.
  expect(JSON.parse(audit.rawResponsePayload.choices[0].message.content)).toEqual(misleadingModelReport)
  return { report, checkpoint, modelInput: JSON.parse(providerBodies[0].messages[1].content) }
}

describe('Final report authority over model-generated action claims', () => {
  it.each([
    { name: 'canonical arguments', args: { host: editedHost, durationMinutes: 17, disable_user: false } },
    { name: 'analyst JSON aliases', args: { host_id: editedHost, duration_minutes: 17, disable_user: false } },
  ])('reports the actual edited target and duration with $name, even when the model claims original approval', async ({ args }) => {
    const { report, checkpoint, modelInput } = await runWithContradictoryModel('edit', args)
    expect(checkpoint.state.decision).toBe('edit')
    expect(checkpoint.state.containmentLogs.find((log: any) => log.hostname)).toMatchObject({ hostname: editedHost, durationMinutes: 17, synthetic: true })
    expect(modelInput.approval).toMatchObject({ target: editedHost, toolArguments: { host: editedHost, durationMinutes: 17, disable_user: false } })
    const actions = report.containmentActions.join('\n')
    const decisions = report.analystDecisions.join('\n')
    expect(actions).toContain(editedHost)
    expect(actions).toMatch(/17/)
    expect(decisions).toMatch(/\bedit\b/i)
    expect(decisions).toContain(editedHost)
    expect(decisions).toMatch(/17/)
    expect(decisions).toContain('false')
    for (const text of [actions, decisions]) {
      expect(text).not.toContain(originalHost)
      expect(text).not.toMatch(/\b45\b/)
      expect(text).not.toContain('approve isolate_host')
    }
    for (const invented of misleadingModelReport.containmentActions) expect(actions).not.toContain(invented)
  })

  it('reports rejection and zero containment actions even when the model claims it executed and approved them', async () => {
    const { report, checkpoint } = await runWithContradictoryModel('reject')
    expect(checkpoint.state.decision).toBe('reject')
    expect(checkpoint.state.containmentLogs).toEqual([])
    const actions = report.containmentActions.join('\n')
    const decisions = report.analystDecisions.join('\n')
    expect(actions).toMatch(/no containment.*executed/i)
    expect(actions).toMatch(/reject/i)
    expect(decisions).toMatch(/\breject\b/i)
    expect(decisions).not.toMatch(/\bapprove\b/i)
    expect(actions).not.toContain(originalHost)
    for (const invented of misleadingModelReport.containmentActions) expect(actions).not.toContain(invented)
  })
})
