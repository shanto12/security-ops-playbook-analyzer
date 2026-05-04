import type { Config } from '@netlify/functions'

function envValue(name: string): string | undefined {
  const netlify = (globalThis as any).Netlify
  return netlify?.env?.get?.(name) ?? process.env[name]
}

function extractJson(text: string): any {
  const direct = text.trim()
  try {
    return JSON.parse(direct)
  } catch {
    const match = direct.match(/\{[\s\S]*\}/)
    if (!match) throw new Error('Provider response did not include JSON')
    return JSON.parse(match[0])
  }
}

function makeLog(input: any) {
  return { id: crypto.randomUUID(), timestamp: new Date().toISOString(), ...input }
}

function list(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item))
  if (typeof value === 'string' && value.trim()) return [value]
  return []
}

function normalizeReport(report: any, incident: any, decision: string) {
  return {
    executiveSummary:
      String(report?.executiveSummary ?? `Investigation for ${incident?.incidentId ?? 'the incident'} completed with analyst decision ${decision}.`),
    rootCause: String(report?.rootCause ?? 'Root cause requires follow-up validation from endpoint and identity teams.'),
    mitreMapping: list(report?.mitreMapping),
    timeline: list(report?.timeline),
    containmentActions: list(report?.containmentActions),
    recommendations: list(report?.recommendations),
    analystDecisions: list(report?.analystDecisions),
    toolResultSummary: list(report?.toolResultSummary),
  }
}

function syntheticTool(name: string, endpoint: string, agent: string, payload: any, body: any) {
  return makeLog({
    callerAgent: agent,
    toolName: name,
    method: 'POST',
    endpointUrl: endpoint,
    requestPayload: payload,
    responsePayload: body,
    latencyMs: 120 + Math.floor(Math.random() * 140),
    tokenCount: body?.usage?.total_tokens,
    status: 'ok',
    type: 'tool',
  })
}

async function fireworksReport(prompt: unknown, send: (event: string, data: unknown) => void) {
  const apiKey = envValue('FIREWORKS_API_KEY')
  if (!apiKey) throw new Error('FIREWORKS_API_KEY is not configured')
  const model = envValue('FIREWORKS_MODEL') || 'accounts/fireworks/models/deepseek-v4-pro'
  const baseUrl = envValue('FIREWORKS_BASE_URL') || 'https://api.fireworks.ai/inference/v1'
  const started = Date.now()
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model,
      temperature: 0.72,
      max_tokens: 620,
      reasoning_effort: 'none',
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content: 'Return compact valid JSON only for a SOC incident report. No markdown.',
        },
        { role: 'user', content: JSON.stringify(prompt) },
      ],
    }),
  })
  const text = await response.text()
  if (!response.ok) throw new Error(`Fireworks ${response.status}: ${text.slice(0, 220)}`)
  const parsed = JSON.parse(text)
  const report = extractJson(parsed?.choices?.[0]?.message?.content ?? '{}')
  send('api_call', makeLog({
    callerAgent: 'Reporting Agent',
    toolName: 'Fireworks',
    method: 'POST',
    endpointUrl: `${baseUrl}/chat/completions`,
    requestPayload: { model, max_tokens: 620, reasoning_effort: 'none' },
    responsePayload: report,
    latencyMs: Date.now() - started,
    tokenCount: parsed?.usage?.total_tokens,
    status: 'ok',
    type: 'llm',
  }))
  return report
}

function checkpoint(node: string, state: Record<string, unknown>, send: (event: string, data: unknown) => void) {
  send('checkpoint', {
    id: `ckpt-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`,
    timestamp: new Date().toISOString(),
    node,
    state,
  })
}

function timeline(title: string, detail: string, outcome: string, send: (event: string, data: unknown) => void, durationMs?: number) {
  send('timeline', {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    title,
    detail,
    outcome,
    durationMs,
  })
}

export default async (req: Request) => {
  if (req.method !== 'POST') return Response.json({ error: 'Method not allowed' }, { status: 405 })
  const encoder = new TextEncoder()
  const startMs = Date.now()
  let payload: any = {}
  try {
    payload = await req.json()
  } catch {
    return Response.json({ error: 'Expected JSON body' }, { status: 400 })
  }

  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: unknown) => controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`))
      const heartbeat = setInterval(() => controller.enqueue(encoder.encode(': keepalive\n\n')), 6000)
      try {
        const incident = payload?.approval?.incident
        const decision = payload?.decision
        send('node_start', { node: 'containment', timestamp: new Date().toISOString() })
        timeline('Command(resume=...) received', `Analyst decision: ${decision}`, decision === 'reject' ? 'warning' : 'success', send)

        const containmentPayload = {
          incident,
          decision,
          editedArguments: payload?.editedArguments,
          approval: payload?.approval,
          executionMode: decision === 'reject' ? 'record_rejection_only' : 'execute_approved_action',
        }
        const logs = []
        if (decision !== 'reject') {
          logs.push(syntheticTool('Firewall', '/api/firewall/block', 'Containment Agent', containmentPayload, {
            ruleName: `block-${incident?.incidentId ?? 'incident'}`,
            action: 'preview_commit',
            target: payload?.approval?.target,
          }))
          logs.push(syntheticTool('EDR', '/api/edr/endpoint', 'Containment Agent', containmentPayload, {
            hostname: incident?.affectedHost,
            containment: 'queued',
            processTreeCaptured: true,
          }))
          logs.push(syntheticTool('Active Directory', '/api/activedirectory/user', 'Containment Agent', containmentPayload, {
            userPrincipalName: incident?.affectedUser,
            accountAction: 'review_required',
            mfaResetRecommended: true,
          }))
        }
        for (const log of logs) send('api_call', log)
        checkpoint('containment_resume', { decision, containmentLogs: logs.map((log) => log.responsePayload) }, send)
        send('node_complete', { node: 'containment', timestamp: new Date().toISOString(), durationMs: Date.now() - startMs })

        for (const node of ['ticketing', 'notification', 'reporting']) {
          send('node_start', { node, timestamp: new Date().toISOString() })
        }
        const ticketPayload = { incident, decision, approval: payload.approval, action: 'post_resume_update' }
        const ticketLogs = [
          syntheticTool('ServiceNow', '/api/servicenow/ticket', 'Ticketing Agent', ticketPayload, {
            number: `INC${Date.now().toString().slice(-7)}`,
            state: 'In Progress',
            assignment_group: 'SOC Tier 2',
          }),
          syntheticTool('Jira', '/api/jira/issue', 'Ticketing Agent', ticketPayload, {
            issueKey: `SEC-${Math.floor(1000 + Math.random() * 9000)}`,
            priority: incident?.severity ?? 'High',
            linkedIncident: incident?.incidentId,
          }),
          syntheticTool('Slack', '/api/slack/notify', 'Notification Agent', ticketPayload, {
            channel: '#soc-war-room',
            deliveryStatus: 'sent',
            incidentId: incident?.incidentId,
          }),
          syntheticTool('Microsoft 365 Audit', '/api/m365/audit', 'Notification Agent', ticketPayload, {
            workload: 'Exchange',
            suspiciousEvents: 2,
            affectedUser: incident?.affectedUser,
          }),
        ]
        ticketLogs.forEach((log) => send('api_call', log))
        send('node_complete', { node: 'ticketing', timestamp: new Date().toISOString(), durationMs: 0 })
        send('node_complete', { node: 'notification', timestamp: new Date().toISOString(), durationMs: 0 })

        const fallbackReport = {
            executiveSummary: `${incident?.severity ?? 'High'} ${incident?.incidentType ?? 'security'} incident ${incident?.incidentId ?? ''} completed the automated investigation and analyst ${decision} path.`,
            rootCause: `Signals indicate activity around ${incident?.affectedUser ?? 'the user'} on ${incident?.affectedHost ?? 'the host'} with IOC ${incident?.iocs?.ip ?? incident?.affectedIp ?? 'unknown'}.`,
            mitreMapping: [incident?.mitreTactic, incident?.mitreTechnique].filter(Boolean),
            timeline: [
              'Incident generated and routed by supervisor',
              'Parallel enrichment and investigation completed',
              `Analyst decision recorded: ${decision}`,
              'Ticketing and notifications completed',
            ],
            containmentActions: logs.map((log) => `${log.toolName}: ${JSON.stringify(log.responsePayload)}`),
            recommendations: ['Validate affected identity sessions', 'Review endpoint process tree', 'Add IOC watchlist expiration', 'Run post-incident control review'],
            analystDecisions: [`${decision} for ${payload?.approval?.actionName ?? 'containment'}`],
            toolResultSummary: ticketLogs.map((log) => `${log.toolName}: ok`),
          }
        let rawReport = fallbackReport
        try {
          rawReport = await fireworksReport(
            {
              incident,
              decision,
              approval: payload.approval,
              containmentResults: logs.map((log) => log.responsePayload),
              ticketingResults: ticketLogs.map((log) => log.responsePayload),
              requiredShape: {
                executiveSummary: 'one sentence',
                rootCause: 'one sentence',
                mitreMapping: ['strings'],
                timeline: ['four short strings'],
                containmentActions: ['strings'],
                recommendations: ['four strings'],
                analystDecisions: ['strings'],
                toolResultSummary: ['strings'],
              },
            },
            send,
          )
        } catch (error) {
          const message = error instanceof Error ? error.message : 'Reporting provider failed'
          send('api_call', makeLog({
            callerAgent: 'Reporting Agent',
            toolName: 'Fireworks',
            method: 'POST',
            endpointUrl: `${envValue('FIREWORKS_BASE_URL') || 'https://api.fireworks.ai/inference/v1'}/chat/completions`,
            requestPayload: { model: envValue('FIREWORKS_MODEL') || 'accounts/fireworks/models/deepseek-v4-pro' },
            responsePayload: { message, fallback: 'deterministic-report' },
            latencyMs: 0,
            status: 'error',
            type: 'error',
          }))
        }
        const report = normalizeReport(rawReport, incident, decision)
        send('delta', { node: 'Reporting Agent', content: JSON.stringify(report) })
        send('report', report)
        checkpoint('reporting', { report }, send)
        send('node_complete', { node: 'reporting', timestamp: new Date().toISOString(), durationMs: Date.now() - startMs })
        const completedAt = new Date().toISOString()
        send('complete', { completedAt, mttrMs: Date.now() - startMs })
        timeline('Incident closed', 'Reporting Agent produced a downloadable investigation report.', 'success', send, Date.now() - startMs)
        send('done', {})
      } catch (error) {
        send('error', { message: error instanceof Error ? error.message : 'Resume failed' })
      } finally {
        clearInterval(heartbeat)
        controller.close()
      }
    },
  })

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store',
      connection: 'keep-alive',
    },
  })
}

export const config: Config = {
  path: '/api/resume-run',
}
