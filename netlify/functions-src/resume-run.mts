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
    if (!match) throw new Error('GLM response did not include JSON')
    return JSON.parse(match[0])
  }
}

function makeLog(input: any) {
  return { id: crypto.randomUUID(), timestamp: new Date().toISOString(), ...input }
}

async function glmJson(node: string, prompt: unknown, send: (event: string, data: unknown) => void, streamDeltas = false) {
  const apiKey = envValue('GLM_API_KEY')
  if (!apiKey) throw new Error('GLM_API_KEY is not configured')
  const model = envValue('GLM_MODEL') || 'glm-5.1'
  const baseUrl = envValue('GLM_BASE_URL') || 'https://api.z.ai/api/coding/paas/v4'
  const started = Date.now()
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      'accept-language': 'en-US,en',
    },
    body: JSON.stringify({
      model,
      thinking: { type: 'disabled' },
      temperature: 0.82,
      max_tokens: 1300,
      stream: streamDeltas,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: 'Return only valid JSON for a SOC incident response workflow.' },
        { role: 'user', content: JSON.stringify(prompt, null, 2) },
      ],
    }),
  })

  if (!streamDeltas) {
    const text = await response.text()
    if (!response.ok) throw new Error(`GLM ${response.status}: ${text.slice(0, 240)}`)
    const parsed = JSON.parse(text)
    const result = extractJson(parsed?.choices?.[0]?.message?.content ?? '{}')
    const log = makeLog({
      callerAgent: node,
      toolName: 'GLM-5.1',
      method: 'POST',
      endpointUrl: `${baseUrl}/chat/completions`,
      requestPayload: { model, thinking: 'disabled', stream: false },
      responsePayload: result,
      latencyMs: Date.now() - started,
      tokenCount: parsed?.usage?.total_tokens,
      status: 'ok',
      type: 'llm',
    })
    send('api_call', log)
    return result
  }

  if (!response.body) throw new Error('GLM stream did not include a body')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let content = ''
  let usage: any
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const frames = buffer.split(/\n\n/)
    buffer = frames.pop() ?? ''
    for (const frame of frames) {
      const line = frame
        .split(/\n/)
        .find((candidate) => candidate.startsWith('data:'))
        ?.slice(5)
        .trim()
      if (!line || line === '[DONE]') continue
      const chunk = JSON.parse(line)
      usage = chunk?.usage ?? usage
      const delta = chunk?.choices?.[0]?.delta?.content ?? ''
      if (delta) {
        content += delta
        send('delta', { node, content: delta })
      }
    }
  }
  const result = extractJson(content)
  send('api_call', makeLog({
    callerAgent: node,
    toolName: 'GLM-5.1',
    method: 'POST',
    endpointUrl: `${baseUrl}/chat/completions`,
    requestPayload: { model, thinking: 'disabled', stream: true },
    responsePayload: result,
    latencyMs: Date.now() - started,
    tokenCount: usage?.total_tokens,
    status: 'ok',
    type: 'llm',
  }))
  return result
}

async function tool(req: Request, name: string, endpoint: string, agent: string, payload: any) {
  const started = Date.now()
  const response = await fetch(new URL(endpoint, req.url), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  })
  const body: any = await response.json()
  return makeLog({
    callerAgent: agent,
    toolName: name,
    method: 'POST',
    endpointUrl: endpoint,
    requestPayload: payload,
    responsePayload: body,
    latencyMs: Date.now() - started,
    tokenCount: body?.usage?.total_tokens,
    status: response.ok ? 'ok' : 'error',
    type: response.ok ? 'tool' : 'error',
  })
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
          logs.push(await tool(req, 'Firewall', '/api/firewall/block', 'Containment Agent', containmentPayload))
          logs.push(await tool(req, 'EDR', '/api/edr/endpoint', 'Containment Agent', containmentPayload))
          logs.push(await tool(req, 'Active Directory', '/api/activedirectory/user', 'Containment Agent', containmentPayload))
        }
        for (const log of logs) send('api_call', log)
        checkpoint('containment_resume', { decision, containmentLogs: logs.map((log) => log.responsePayload) }, send)
        send('node_complete', { node: 'containment', timestamp: new Date().toISOString(), durationMs: Date.now() - startMs })

        for (const node of ['ticketing', 'notification', 'reporting']) {
          send('node_start', { node, timestamp: new Date().toISOString() })
        }
        const ticketPayload = { incident, decision, approval: payload.approval, action: 'post_resume_update' }
        const ticketLogs = await Promise.all([
          tool(req, 'ServiceNow', '/api/servicenow/ticket', 'Ticketing Agent', ticketPayload),
          tool(req, 'Jira', '/api/jira/issue', 'Ticketing Agent', ticketPayload),
          tool(req, 'Slack', '/api/slack/notify', 'Notification Agent', ticketPayload),
          tool(req, 'Microsoft 365 Audit', '/api/m365/audit', 'Notification Agent', ticketPayload),
        ])
        ticketLogs.forEach((log) => send('api_call', log))
        send('node_complete', { node: 'ticketing', timestamp: new Date().toISOString(), durationMs: 0 })
        send('node_complete', { node: 'notification', timestamp: new Date().toISOString(), durationMs: 0 })

        const report = await glmJson(
          'Reporting Agent',
          {
            incident,
            decision,
            approval: payload.approval,
            priorCheckpoints: payload.checkpoints,
            priorTimeline: payload.timeline,
            priorApiLogs: payload.apiLogs,
            postResumeToolLogs: [...logs, ...ticketLogs],
            task: 'Compile a concise final incident report.',
            returnShape: {
              executiveSummary: 'paragraph',
              rootCause: 'paragraph',
              mitreMapping: ['tactic/technique strings'],
              timeline: ['chronological strings'],
              containmentActions: ['strings'],
              recommendations: ['strings'],
              analystDecisions: ['strings'],
              toolResultSummary: ['strings'],
            },
          },
          send,
          true,
        )
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
