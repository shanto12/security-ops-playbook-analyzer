import { expect, test } from '@playwright/test'
import type { Page } from '@playwright/test'
import { toolEndpoints } from '../src/data/graph'

const incident = {
  incidentId: 'SOC-E2E-9001',
  timestamp: '2026-05-04T14:00:00.000Z',
  severity: 'High',
  priorityScore: 8,
  incidentType: 'credential access',
  affectedUser: 'analyst@example.com',
  affectedHost: 'WS-E2E-001',
  affectedIp: '10.20.30.40',
  affectedDepartment: 'Finance',
  mitreTactic: 'Credential Access',
  mitreTechnique: 'T1003 OS Credential Dumping',
  initialAlertSource: 'EDR',
  iocs: {
    ip: '203.0.113.44',
    hash: 'b'.repeat(64),
    domain: 'stage-e2e.example',
    url: 'https://stage-e2e.example/payload',
  },
  rawLogSnippet: '2026-05-04T14:00:00Z EDR suspicious credential access on WS-E2E-001',
}

const approval = {
  runId: 'run-e2e',
  actionName: 'isolate_host',
  target: 'WS-E2E-001',
  toolArguments: { host: 'WS-E2E-001', durationMinutes: 45, ticket: 'SOC-E2E-9001' },
  riskJustification: 'Host isolation reduces credential theft blast radius.',
  severity: 'High',
  expiresAt: '2026-05-04T14:01:00.000Z',
  incident,
  stateSnapshot: { threadId: 'thread-e2e' },
}

const report = {
  executiveSummary: 'The investigation confirmed credential access activity and completed approved containment.',
  rootCause: 'Credential dumping behavior on WS-E2E-001 matched the suspicious IOC set.',
  mitreMapping: ['Credential Access', 'T1003 OS Credential Dumping'],
  timeline: ['Incident generated', 'Tool enrichment completed', 'Containment approved', 'Report generated'],
  containmentActions: ['Firewall block staged', 'EDR isolation queued'],
  recommendations: ['Rotate credentials', 'Review EDR process tree', 'Hunt related hosts', 'Expire IOC blocks after review'],
  analystDecisions: ['approve isolate_host'],
  toolResultSummary: toolEndpoints.map((tool) => `${tool.name}: ok`),
}

function sse(events: Array<{ event: string; data: unknown }>) {
  return events.map((item) => `event: ${item.event}\ndata: ${JSON.stringify(item.data)}\n\n`).join('')
}

async function routeBaseApis(page: Page) {
  await page.route('**/api/health', async (route) => {
    await route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        service: 'soc-ai-agent-demo',
        status: 'ok',
        mode: 'live-glm',
        provider: 'z.ai + fireworks',
        model: 'glm-5.1',
        toolModel: 'glm-5-turbo',
        endpoint: 'https://api.z.ai/api/coding/paas/v4',
        checkedAt: new Date().toISOString(),
        capabilities: {},
        models: ['glm-5.1', 'glm-5-turbo'],
      }),
    })
  })

  await page.route('**/api/agent-run', async (route) => {
    await route.fulfill({
      contentType: 'text/event-stream',
      body: sse([
        { event: 'start', data: { runId: 'run-e2e', threadId: 'thread-e2e', startedAt: new Date().toISOString() } },
        { event: 'node_start', data: { node: 'incident_generator', timestamp: new Date().toISOString() } },
        {
          event: 'api_call',
          data: {
            id: 'llm-supervisor',
            timestamp: new Date().toISOString(),
            callerAgent: 'Supervisor Graph Orchestrator',
            toolName: 'Fireworks',
            provider: 'fireworks',
            model: 'accounts/fireworks/models/deepseek-v4-pro',
            method: 'POST',
            endpointUrl: 'https://api.fireworks.ai/inference/v1/chat/completions',
            requestPayload: { body: { messages: [{ role: 'user', content: 'generate incident' }] } },
            rawResponsePayload: { id: 'chatcmpl-e2e' },
            parsedResponsePayload: { incident },
            responsePayload: { normalizedOutput: { incident } },
            latencyMs: 120,
            tokenCount: 444,
            statusCode: 200,
            status: 'ok',
            type: 'llm',
          },
        },
        { event: 'incident', data: incident },
        { event: 'checkpoint', data: { id: 'ckpt-e2e', timestamp: new Date().toISOString(), node: 'incident_generator', state: { incident } } },
        { event: 'timeline', data: { id: 'tl-e2e', timestamp: new Date().toISOString(), title: 'Run started', detail: 'E2E run', outcome: 'info' } },
        { event: 'tool_fanout_required', data: { incident, state: {}, tools: toolEndpoints, concurrency: 1, evidenceRequirement: 'e2e' } },
        { event: 'approval_required', data: approval },
        { event: 'done', data: {} },
      ]),
    })
  })

  for (const [index, tool] of toolEndpoints.entries()) {
    await page.route(`**${tool.endpoint}`, async (route) => {
      const tokenCount = 700 + index
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          tool: tool.name,
          endpoint: tool.endpoint,
          generatedAt: new Date().toISOString(),
          incidentId: incident.incidentId,
          data: { verdict: 'suspicious', evidence: `${tool.name} observed ${incident.iocs.ip}` },
          llmAudit: {
            id: `audit-${tool.name}`,
            timestamp: new Date().toISOString(),
            callerAgent: `${tool.name} Tool Simulator`,
            toolName: 'GLM-5.1',
            provider: 'z.ai',
            model: 'glm-5-turbo',
            method: 'POST',
            endpointUrl: 'https://api.z.ai/api/coding/paas/v4/chat/completions',
            requestPayload: { body: { messages: [{ role: 'user', content: `simulate ${tool.name}` }] } },
            rawResponsePayload: { choices: [{ message: { content: '{"verdict":"suspicious"}' } }] },
            parsedResponsePayload: { verdict: 'suspicious', tool: tool.name },
            responsePayload: { normalizedOutput: { verdict: 'suspicious', tool: tool.name } },
            latencyMs: 90 + index,
            tokenCount,
            statusCode: 200,
            status: 'ok',
            type: 'llm',
          },
        }),
      })
    })
  }

  await page.route('**/api/replay-run', async (route) => {
    await route.fulfill({
      contentType: 'text/event-stream',
      body: sse([
        { event: 'node_start', data: { node: 'supervisor', timestamp: new Date().toISOString() } },
        { event: 'timeline', data: { id: 'fork-e2e-tl', timestamp: new Date().toISOString(), title: 'Forked ckpt-e2e', detail: 'Alternate branch tested', outcome: 'info' } },
        { event: 'checkpoint', data: { id: 'fork-e2e', timestamp: new Date().toISOString(), node: 'time_travel_fork', state: { branchName: 'alternate' } } },
        { event: 'node_complete', data: { node: 'supervisor', timestamp: new Date().toISOString(), durationMs: 10 } },
        { event: 'done', data: {} },
      ]),
    })
  })
}

test('completes incident, tool evidence, approval, final report, exports, and replay', async ({ page }) => {
  test.setTimeout(60_000)
  await routeBaseApis(page)
  await page.route('**/api/resume-run', async (route) => {
    await route.fulfill({
      contentType: 'text/event-stream',
      body: sse([
        { event: 'node_start', data: { node: 'reporting', timestamp: new Date().toISOString() } },
        {
          event: 'api_call',
          data: {
            id: 'report-llm',
            timestamp: new Date().toISOString(),
            callerAgent: 'Reporting Agent',
            toolName: 'GLM-5.1',
            provider: 'z.ai',
            model: 'glm-5.1',
            method: 'POST',
            endpointUrl: 'https://api.z.ai/api/coding/paas/v4/chat/completions',
            requestPayload: { body: { messages: [{ role: 'user', content: 'final report' }] } },
            rawResponsePayload: { choices: [{ message: { content: JSON.stringify(report) } }] },
            parsedResponsePayload: report,
            responsePayload: { normalizedOutput: report },
            latencyMs: 180,
            tokenCount: 1400,
            statusCode: 200,
            status: 'ok',
            type: 'llm',
          },
        },
        { event: 'report', data: report },
        { event: 'checkpoint', data: { id: 'ckpt-report', timestamp: new Date().toISOString(), node: 'reporting', state: { report } } },
        { event: 'node_complete', data: { node: 'reporting', timestamp: new Date().toISOString(), durationMs: 180 } },
        { event: 'complete', data: { completedAt: new Date().toISOString(), mttrMs: 180 } },
        { event: 'timeline', data: { id: 'closed', timestamp: new Date().toISOString(), title: 'Incident closed', detail: 'Report generated', outcome: 'success' } },
        { event: 'done', data: {} },
      ]),
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: /Generate Incident/i }).click()
  const approve = page.getByRole('button', { name: /^Approve$/i })
  await expect(approve).toBeDisabled()
  await expect(page.locator('details.apiRow.tool')).toHaveCount(toolEndpoints.length, { timeout: 20_000 })
  await expect(approve).toBeEnabled()
  await approve.click()

  const finalReport = page.locator('#final-report')
  await expect(finalReport.getByText('Executive Summary')).toBeVisible()
  await expect(finalReport.getByText('Investigation Timeline')).toBeVisible()
  await expect(finalReport.getByText('Containment Actions')).toBeVisible()
  await expect(finalReport.getByText('Analyst Decisions')).toBeVisible()
  await expect(finalReport.getByText('Tool Result Summary')).toBeVisible()
  await expect(finalReport.getByText('VirusTotal: ok')).toBeVisible()
  await expect(finalReport.getByRole('button', { name: 'PDF' })).toBeEnabled()

  const download = page.waitForEvent('download')
  await finalReport.getByRole('button', { name: 'JSON' }).click()
  expect((await download).suggestedFilename()).toBe('soc-run-export.json')

  const popup = page.waitForEvent('popup')
  await finalReport.getByRole('button', { name: 'PDF' }).click()
  await expect((await popup).locator('h1')).toContainText('SOC AI Agent Incident Report')

  await page.getByRole('button', { name: 'Fork' }).first().click()
  await expect(page.getByText('Forked ckpt-e2e')).toBeVisible()
})

test('keeps approval available when resume returns an error event', async ({ page }) => {
  test.setTimeout(60_000)
  await routeBaseApis(page)
  await page.route('**/api/resume-run', async (route) => {
    await route.fulfill({
      contentType: 'text/event-stream',
      body: sse([
        { event: 'error', data: { message: 'Report model unavailable' } },
        { event: 'done', data: {} },
      ]),
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: /Generate Incident/i }).click()
  await expect(page.locator('details.apiRow.tool')).toHaveCount(toolEndpoints.length, { timeout: 20_000 })
  await page.getByRole('button', { name: /^Approve$/i }).click()

  await expect(page.getByText('Report model unavailable')).toBeVisible()
  await expect(page.getByRole('button', { name: /^Approve$/i })).toBeVisible()
  await expect(page.getByText('Approval is ready. The Reporting Agent will compile the RCA after analyst decision.')).toBeVisible()
})
