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
  modelName,
}: {
  node: string
  prompt: unknown
  temperature?: number
  maxTokens?: number
  send: (event: string, data: unknown) => void
  streamDeltas?: boolean
  modelName?: string
}) {
  const apiKey = requiredKey()
  const model = modelName || envValue('GLM_MODEL') || 'glm-5.1'
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

function buildToolRequest(tool: (typeof toolEndpoints)[number], incident: any, state: any) {
  return {
    incident,
    state,
    action: tool.name === 'Firewall' ? 'preview_block_rule' : 'investigate',
    requestTimestamp: new Date().toISOString(),
  }
}

function buildHostedToolResult(
  tool: (typeof toolEndpoints)[number],
  incident: any,
  state: any,
  generated: any,
  index: number,
  sourceLatencyMs: number,
) {
  const requestPayload = {
    ...buildToolRequest(tool, incident, state),
    hostedExecution: 'batched_glm_superstep',
  }
  const body = {
    tool: tool.name,
    endpoint: tool.endpoint,
    generatedAt: new Date().toISOString(),
    incidentId: incident?.incidentId,
    model: envValue('GLM_TOOL_MODEL') || 'glm-5-turbo',
    mode: 'hosted-batched-superstep',
    data: generated?.responsePayload ?? generated?.data ?? generated,
  }

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
      latencyMs: Math.max(90, Math.round(sourceLatencyMs / toolEndpoints.length) + index * 11),
      tokenCount: generated?.tokenCount,
      status: 'ok',
      type: 'tool',
    }),
  }
}

function pickGeneratedTool(outputs: any[], tool: (typeof toolEndpoints)[number], index: number) {
  return (
    outputs.find((item) => item?.name === tool.name || item?.toolName === tool.name || item?.endpoint === tool.endpoint) ??
    outputs[index] ?? {
      responsePayload: {
        finding: 'GLM omitted this tool response from the batch.',
        confidence: 'low',
      },
    }
  )
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
        const orchestratedRun = await callGlmJson({
          node: 'Supervisor Graph Orchestrator',
          prompt: {
            task:
              'Generate a complete one-click SOC incident investigation run for a hosted LangGraph demo. Return compact JSON only.',
            diversitySeed: `${Date.now()}-${crypto.randomUUID()}`,
            incidentSchema: {
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
            toolContracts: toolEndpoints.map((tool) => ({
              name: tool.name,
              endpoint: tool.endpoint,
              agent: tool.agent,
            })),
            returnShape: {
              incident: 'full incident object',
              supervisor: {
                route: 'more_investigation | containment | escalation',
                rationale: 'short explanation',
                selectedAgents: ['agent names'],
                confidence: '0-1 number',
              },
              triage: {
                classification: 'string',
                dedupeStatus: 'new | duplicate | related',
                riskScore: '1-100',
                keyFindings: ['strings'],
              },
              toolResults:
                'exactly one compact object per toolContract with name, endpoint, responsePayload, confidence, and tokenCount',
              containment: {
                actionName: 'isolate_host | disable_user | block_ip_or_domain',
                target: 'host/user/ip/domain',
                toolArguments: {},
                riskJustification: 'why this action is appropriate and what it could break',
              },
            },
            rules: [
              'Every incident field must vary independently from run to run.',
              'Every tool response must include at least one incident IOC or affected entity.',
              'Use very compact enterprise schemas: each responsePayload should have verdict, confidence, and exactly two evidence strings.',
              'Make the supervisor, triage, tool responses, and containment recommendation mutually consistent.',
            ],
          },
          temperature: 0.9,
          maxTokens: 1000,
          send,
          streamDeltas: false,
          modelName: envValue('GLM_TOOL_MODEL') || 'glm-5-turbo',
        })
        const streamPreview = JSON.stringify(orchestratedRun.result)
        for (let index = 0; index < streamPreview.length; index += 96) {
          send('delta', {
            node: 'Supervisor Graph Orchestrator',
            content: streamPreview.slice(index, index + 96),
          })
        }
        const runPlan = orchestratedRun.result
        const incident = runPlan.incident
        const supervisorResult = runPlan.supervisor ?? {}
        const triageResult = runPlan.triage ?? {}
        const generatedTools = Array.isArray(runPlan.toolResults) ? runPlan.toolResults : []
        const state = { supervisor: supervisorResult, triage: triageResult }

        send('incident', incident)
        checkpoint('incident_generator', { incident, threadId }, send)
        send('node_complete', {
          node: 'incident_generator',
          timestamp: new Date().toISOString(),
          durationMs: orchestratedRun.log.latencyMs,
          summary: incident?.incidentId,
        })

        send('node_start', { node: 'supervisor', timestamp: new Date().toISOString() })
        timeline('Supervisor routed incident', supervisorResult.rationale ?? 'Routing complete.', 'success', send)
        checkpoint('supervisor', { incidentId: incident?.incidentId, supervisor: supervisorResult }, send)
        send('node_complete', { node: 'supervisor', timestamp: new Date().toISOString(), durationMs: 0 })

        send('node_start', { node: 'triage', timestamp: new Date().toISOString() })
        timeline('Triage completed', triageResult.classification ?? 'Incident classified.', 'success', send)
        checkpoint('triage', { triage: triageResult }, send)
        send('node_complete', { node: 'triage', timestamp: new Date().toISOString(), durationMs: 0 })

        timeline(
          'Parallel superstep started',
          'Enrichment, identity, endpoint, log, cloud, and ticketing tools are represented as a hosted Send() fan-out batch.',
          'info',
          send,
        )
        for (const node of ['enrichment', 'identity', 'endpoint', 'log_analysis', 'threat_intel']) {
          send('node_start', { node, timestamp: new Date().toISOString() })
        }
        const toolResults = toolEndpoints.map((tool, index) =>
          buildHostedToolResult(
            tool,
            incident,
            state,
            pickGeneratedTool(generatedTools, tool, index),
            index,
            orchestratedRun.log.latencyMs,
          ),
        )
        toolResults.forEach((item) => send('api_call', item.log))
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
        const containment = runPlan.containment ?? {}
        const approval = {
          runId,
          actionName: containment.actionName ?? 'isolate_host',
          target: containment.target ?? incident?.affectedHost,
          toolArguments: containment.toolArguments ?? {
            host: incident?.affectedHost,
            durationMinutes: 45,
            ticket: incident?.incidentId,
          },
          riskJustification:
            containment.riskJustification ??
            'Containment may disrupt business workflow but prevents additional attacker movement.',
          severity: incident?.severity,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          incident,
          stateSnapshot: {
            threadId,
            supervisor: supervisorResult,
            triage: triageResult,
            toolResults: toolResults.map((item) => ({ tool: item.tool.name, response: (item.body as any)?.data ?? item.body })),
          },
        }
        checkpoint('containment_interrupt', { approval }, send)
        timeline('Containment paused', 'LangGraph interrupt surfaced a human approval card.', 'warning', send)
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
