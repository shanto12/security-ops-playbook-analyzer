import { afterEach, describe, expect, it, vi } from 'vitest'
import { getProvider } from '../netlify/lib/provider'
import health from '../netlify/functions-src/health.mts'
import resumeRun from '../netlify/functions-src/resume-run.mts'
import { consumeSse } from '../src/lib/sse'

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs() })
describe('Provider routing and honest health', () => {
  it('prefers configured DeepSeek with accurate names while allowing explicit GLM selection', () => {
    vi.stubEnv('DEEPSEEK_API_KEY', 'unit-test')
    vi.stubEnv('GLM_API_KEY', 'unit-test-other')
    expect(getProvider()).toMatchObject({ provider: 'DeepSeek', model: 'deepseek-flash', baseUrl: 'https://api.deepseek.com' })
    vi.stubEnv('AI_PROVIDER', 'glm')
    expect(getProvider('tool')).toMatchObject({ provider: 'Z.ai', model: 'glm-5-turbo' })
  })
  it('does not label key presence as healthy when upstream rejects it', async () => {
    vi.stubEnv('DEEPSEEK_API_KEY', 'unit-test')
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: 'quota' }, { status: 429 })))
    const result = await (await health()).json()
    expect(result).toMatchObject({ status: 'degraded', mode: 'unavailable', provider: 'DeepSeek' })
    expect(JSON.stringify(result)).not.toContain('unit-test')
  })
  it('reports reachable model catalog separately from generation quota', async () => {
    vi.stubEnv('DEEPSEEK_API_KEY', 'unit-test')
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ data: [{ id: 'deepseek-flash' }] })))
    const result = await (await health()).json()
    expect(result).toMatchObject({ status: 'ok', mode: 'live-deepseek', capabilities: { enterprise_tool_endpoints: false } })
    expect(result.healthDetail).toContain('quota is checked when a run starts')
  })
  it('never emits complete when report model fails', async () => {
    vi.stubEnv('DEEPSEEK_API_KEY', 'unit-test')
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ error: 'quota' }, { status: 429 })))
    const response = await resumeRun(new Request('https://example.test/api/resume-run', { method: 'POST', body: JSON.stringify({ decision: 'reject', approval: { runId: 'test', incident: { incidentId: 'unit' } } }) }))
    const events: { event: string }[] = []
    await consumeSse(response, event => events.push(event))
    expect(events.some(e => e.event === 'error')).toBe(true)
    expect(events.some(e => e.event === 'complete')).toBe(false)
  })
  it('applies edited target and duration to execution evidence and report input', async () => {
    vi.stubEnv('DEEPSEEK_API_KEY', 'unit-test')
    const requestBodies: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (_url, options) => {
      requestBodies.push(options.body)
      return Response.json({ choices: [{ message: { content: JSON.stringify({ executiveSummary: 'Edited synthetic action.', rootCause: 'Test' }) } }], usage: { total_tokens: 10 } })
    }))
    const response = await resumeRun(new Request('https://example.test/api/resume-run', { method: 'POST', body: JSON.stringify({ decision: 'edit', editedArguments: { host: 'EDITED-HOST', durationMinutes: 17 }, approval: { runId: 'test', target: 'ORIGINAL-HOST', toolArguments: { host: 'ORIGINAL-HOST', durationMinutes: 45 }, incident: { incidentId: 'unit', affectedHost: 'ORIGINAL-HOST' } } }) }))
    const events: { event: string; data: any }[] = []
    await consumeSse(response, event => events.push(event))
    const containment = events.find(e => e.event === 'checkpoint' && e.data.node === 'containment_resume')
    expect(containment?.data.state.containmentLogs[1]).toMatchObject({ hostname: 'EDITED-HOST', durationMinutes: 17 })
    const modelInput = JSON.parse(JSON.parse(requestBodies[0]).messages[1].content)
    expect(modelInput.approval).toMatchObject({ target: 'EDITED-HOST', toolArguments: { host: 'EDITED-HOST', durationMinutes: 17 } })
    expect(events.some(e => e.event === 'complete')).toBe(true)
  })

})
