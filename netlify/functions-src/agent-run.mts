import type { Config } from '@netlify/functions'

type ApiLogEntry = {
  id: string
  timestamp: string
  callerAgent: string
  toolName: string
  method: string
  endpointUrl: string
  requestPayload: unknown
  responsePayload: unknown
  latencyMs: number
  tokenCount?: number
  status: 'ok' | 'error'
  type: 'llm' | 'tool' | 'human' | 'error'
}

const toolEndpoints = [
  { name: 'VirusTotal', endpoint: '/api/virustotal/lookup', agent: 'Enrichment Agent' },
  { name: 'AbuseIPDB', endpoint: '/api/abuseipdb/check', agent: 'Enrichment Agent' },
  { name: 'Active Directory', endpoint: '/api/activedirectory/user', agent: 'Identity Investigation Agent' },
  { name: 'Okta', endpoint: '/api/okta/user-risk', agent: 'Identity Investigation Agent' },
  { name: 'EDR', endpoint: '/api/edr/endpoint', agent: 'Endpoint Investigation Agent' },
  { name: 'SIEM', endpoint: '/api/siem/search', agent: 'Log Analysis Agent' },
  { name: 'Microsoft 365 Audit', endpoint: '/api/m365/audit', agent: 'Log Analysis Agent' },
  { name: 'AWS CloudTrail', endpoint: '/api/cloudtrail/search', agent: 'Log Analysis Agent' },
  { name: 'ServiceNow', endpoint: '/api/servicenow/ticket', agent: 'Ticketing Agent' },
  { name: 'Jira', endpoint: '/api/jira/issue', agent: 'Ticketing Agent' },
]

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

function makeLog(input: Omit<ApiLogEntry, 'id' | 'timestamp'>): ApiLogEntry {
  return { id: crypto.randomUUID(), timestamp: new Date().toISOString(), ...input }
}

function requiredKey() {
  const apiKey = envValue('GLM_API_KEY')
  if (!apiKey) throw new Error('GLM_API_KEY is not configured')
  return apiKey
}

async function callGlmJson({
  node,
  prompt,
  temperature = 0.82,
  maxTokens = 900,
  send,
  streamDeltas = false,
}: {
  node: string
  prompt: unknown
  temperature?: number
  maxTokens?: number
  send: (event: string, data: unknown) => void
  streamDeltas?: boolean
}) {
  const apiKey = requiredKey()
  const model = envValue('GLM_MODEL') || 'glm-5.1'
  const baseUrl = envValue('GLM_BASE_URL') || 'https://api.z.ai/api/coding/paas/v4'
  const body = {
    model,
    thinking: { type: 'disabled' },
    temperature,
    max_tokens: maxTokens,
    stream: streamDeltas,
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content:
          'You are an enterprise SOC multi-agent orchestration engine. Return only valid JSON. Do not use markdown.',
      },
      { role: 'user', content: typeof prompt === 'string' ? prompt : JSON.stringify(prompt, null, 2) },
    ],
  }
  const started = Date.now()
  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json',
      'accept-language': 'en-US,en',
    },
    body: JSON.stringify(body),
  })

  if (!streamDeltas) {
    const text = await response.text()
    if (!response.ok) throw new Error(`GLM ${response.status}: ${text.slice(0, 240)}`)
    const parsed = JSON.parse(text)
    const content = parsed?.choices?.[0]?.message?.content ?? '{}'
    const result = extractJson(content)
    const log = makeLog({
      callerAgent: node,
      toolName: 'GLM-5.1',
      method: 'POST',
      endpointUrl: `${baseUrl}/chat/completions`,
      requestPayload: { model, temperature, max_tokens: maxTokens, thinking: 'disabled' },
      responsePayload: result,
      latencyMs: Date.now() - started,
      tokenCount: parsed?.usage?.total_tokens,
      status: 'ok',
      type: 'llm',
    })
    send('api_call', log)
    return { result, log }
  }

  if (!response.ok || !response.body) {
    const text = await response.text().catch(() => '')
    throw new Error(`GLM stream failed ${response.status}: ${text.slice(0, 240)}`)
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let content = ''
  let usage: any = undefined
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
  const log = makeLog({
    callerAgent: node,
    toolName: 'GLM-5.1',
    method: 'POST',
    endpointUrl: `${baseUrl}/chat/completions`,
    requestPayload: { model, temperature, max_tokens: maxTokens, stream: true, thinking: 'disabled' },
    responsePayload: result,
    latencyMs: Date.now() - started,
    tokenCount: usage?.total_tokens,
    status: 'ok',
    type: 'llm',
  })
  send('api_call', log)
  return { result, log }
}

async function callTool(req: Request, tool: (typeof toolEndpoints)[number], incident: any, state: any) {
  const requestPayload = {
    incident,
    state,
    action: tool.name === 'Firewall' ? 'preview_block_rule' : 'investigate',
    requestTimestamp: new Date().toISOString(),
  }
  const started = Date.now()
  try {
    const response = await fetch(new URL(tool.endpoint, req.url), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(requestPayload),
    })
    const body: any = await response.json()
    return {
      tool,
      body,
      log: makeLog({
        callerAgent: tool.agent,
        toolName: tool.name,
        method: 'POST',
        endpointUrl: tool.endpoint,
        requestPayload,
        responsePayload: body,
        latencyMs: Date.now() - started,
        tokenCount: body?.usage?.total_tokens,
        status: response.ok ? 'ok' : 'error',
        type: response.ok ? 'tool' : 'error',
      }),
    }
  } catch (error) {
    return {
      tool,
      body: { error: error instanceof Error ? error.message : 'Tool call failed' },
      log: makeLog({
        callerAgent: tool.agent,
        toolName: tool.name,
        method: 'POST',
        endpointUrl: tool.endpoint,
        requestPayload,
        responsePayload: { error: error instanceof Error ? error.message : 'Tool call failed' },
        latencyMs: Date.now() - started,
        status: 'error',
        type: 'error',
      }),
    }
  }
}

async function callToolsInWaves(
  req: Request,
  incident: any,
  state: any,
  send: (event: string, data: unknown) => void,
) {
  const results: Awaited<ReturnType<typeof callTool>>[] = []
  const waveSize = 5
  for (let index = 0; index < toolEndpoints.length; index += waveSize) {
    const wave = toolEndpoints.slice(index, index + waveSize)
    timeline(
      `Parallel wave ${Math.floor(index / waveSize) + 1}`,
      `Calling ${wave.map((tool) => tool.name).join(', ')} via real HTTP endpoints.`,
      'info',
      send,
    )
    const settled = await Promise.all(wave.map((tool) => callTool(req, tool, incident, state)))
    settled.forEach((item) => {
      results.push(item)
      send('api_call', item.log)
    })
  }
  return results
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
  const startedAt = new Date().toISOString()
  const startMs = Date.now()

  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`))
      }
      const heartbeat = setInterval(() => controller.enqueue(encoder.encode(': keepalive\n\n')), 6000)
      const runId = `run-${crypto.randomUUID().slice(0, 8)}`
      const threadId = `thread-${crypto.randomUUID().slice(0, 12)}`

      try {
        requiredKey()
        send('start', { runId, threadId, startedAt })
        timeline('Run started', 'Supervisor accepted a new one-click incident investigation.', 'info', send)

        send('node_start', { node: 'incident_generator', timestamp: new Date().toISOString() })
        const incidentPrompt = {
          task: 'Generate one unique enterprise cybersecurity incident.',
          schema: {
            incidentId: 'SOC-YYYYMMDD-random',
            timestamp: 'ISO-8601',
            severity: 'Critical | High | Medium | Low',
            priorityScore: '1-10 integer',
            incidentType:
              'phishing | ransomware | lateral movement | data exfiltration | privilege escalation | C2 beaconing | insider threat | brute force | supply chain compromise | zero-day exploit',
            affectedUser: 'realistic corporate user',
            affectedHost: 'hostname',
            affectedIp: 'RFC1918 or public IP as appropriate',
            affectedDepartment: 'department',
            mitreTactic: 'MITRE ATT&CK tactic',
            mitreTechnique: 'MITRE technique ID and name',
            initialAlertSource: 'SIEM | EDR | NDR | UEBA',
            iocs: { ip: 'indicator IP', hash: 'sha256', domain: 'domain', url: 'url' },
            rawLogSnippet: '3-6 lines of plausible log evidence',
          },
          diversity: `Every field must vary independently. Seed ${Date.now()}-${Math.random()}.`,
        }
        const incidentCall = await callGlmJson({
          node: 'Incident Generator',
          prompt: incidentPrompt,
          temperature: 0.92,
          maxTokens: 760,
          send,
          streamDeltas: true,
        })
        const incident = incidentCall.result
        send('incident', incident)
        checkpoint('incident_generator', { incident, threadId }, send)
        send('node_complete', {
          node: 'incident_generator',
          timestamp: new Date().toISOString(),
          durationMs: incidentCall.log.latencyMs,
          summary: incident.incidentId,
        })

        send('node_start', { node: 'supervisor', timestamp: new Date().toISOString() })
        const supervisor = await callGlmJson({
          node: 'Supervisor Agent',
          prompt: {
            incident,
            task: 'Decide which specialist subgraphs should run and the investigation strategy.',
            returnShape: {
              route: 'more_investigation | containment | escalation',
              rationale: 'short explanation',
              selectedAgents: ['agent names'],
              confidence: '0-1 number',
            },
          },
          send,
          maxTokens: 420,
        })
        timeline('Supervisor routed incident', supervisor.result.rationale ?? 'Routing complete.', 'success', send, supervisor.log.latencyMs)
        checkpoint('supervisor', { incidentId: incident.incidentId, supervisor: supervisor.result }, send)
        send('node_complete', { node: 'supervisor', timestamp: new Date().toISOString(), durationMs: supervisor.log.latencyMs })

        send('node_start', { node: 'triage', timestamp: new Date().toISOString() })
        const triage = await callGlmJson({
          node: 'Triage Agent',
          prompt: {
            incident,
            supervisor: supervisor.result,
            task: 'Classify the incident, assign risk, and check likely deduplication against synthetic prior incidents.',
            returnShape: {
              classification: 'string',
              dedupeStatus: 'new | duplicate | related',
              riskScore: '1-100',
              keyFindings: ['strings'],
            },
          },
          send,
          maxTokens: 500,
        })
        timeline('Triage completed', triage.result.classification ?? 'Incident classified.', 'success', send, triage.log.latencyMs)
        checkpoint('triage', { triage: triage.result }, send)
        send('node_complete', { node: 'triage', timestamp: new Date().toISOString(), durationMs: triage.log.latencyMs })

        timeline('Parallel superstep started', 'Enrichment, identity, endpoint, log, cloud, ticket, and notification tools are running together.', 'info', send)
        for (const node of ['enrichment', 'identity', 'endpoint', 'log_analysis', 'threat_intel']) {
          send('node_start', { node, timestamp: new Date().toISOString() })
        }
        const toolResults = await callToolsInWaves(req, incident, { supervisor: supervisor.result, triage: triage.result }, send)
        checkpoint(
          'parallel_superstep',
          {
            toolCount: toolResults.length,
            successfulTools: toolResults.filter((item) => item.log.status === 'ok').map((item) => item.tool.name),
          },
          send,
        )
        for (const node of ['enrichment', 'identity', 'endpoint', 'log_analysis', 'threat_intel']) {
          send('node_complete', { node, timestamp: new Date().toISOString(), durationMs: 0 })
        }

        send('node_start', { node: 'containment', timestamp: new Date().toISOString() })
        const containment = await callGlmJson({
          node: 'Containment Agent',
          prompt: {
            incident,
            triage: triage.result,
            toolResults: toolResults.map((item) => ({ tool: item.tool.name, data: (item.body as any)?.data ?? item.body })),
            task: 'Recommend one containment action that requires human approval. Return realistic tool arguments.',
            returnShape: {
              actionName: 'isolate_host | disable_user | block_ip_or_domain',
              target: 'host/user/ip/domain',
              toolArguments: {},
              riskJustification: 'why this action is appropriate and what it could break',
            },
          },
          send,
          maxTokens: 520,
        })
        const approval = {
          runId,
          actionName: containment.result.actionName ?? 'isolate_host',
          target: containment.result.target ?? incident.affectedHost,
          toolArguments: containment.result.toolArguments ?? {
            host: incident.affectedHost,
            durationMinutes: 45,
            ticket: incident.incidentId,
          },
          riskJustification:
            containment.result.riskJustification ??
            'Containment may disrupt business workflow but prevents additional attacker movement.',
          severity: incident.severity,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          incident,
          stateSnapshot: {
            threadId,
            supervisor: supervisor.result,
            triage: triage.result,
            toolResults: toolResults.map((item) => ({ tool: item.tool.name, response: (item.body as any)?.data ?? item.body })),
          },
        }
        checkpoint('containment_interrupt', { approval }, send)
        timeline('Containment paused', 'LangGraph interrupt surfaced a human approval card.', 'warning', send, containment.log.latencyMs)
        send('approval_required', approval)
        send('done', {})
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Agent run failed'
        send('error', { message })
        send('api_call', makeLog({
          callerAgent: 'Runtime',
          toolName: 'Agent Run',
          method: req.method,
          endpointUrl: '/api/agent-run',
          requestPayload: {},
          responsePayload: { message },
          latencyMs: Date.now() - startMs,
          status: 'error',
          type: 'error',
        }))
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
  path: '/api/agent-run',
}
