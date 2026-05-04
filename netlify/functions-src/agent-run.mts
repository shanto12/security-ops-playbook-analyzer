import type { Config } from '@netlify/functions'

type ApiLogEntry = {
  id: string
  timestamp: string
  callerAgent: string
  toolName: string
  provider?: string
  model?: string
  baseUrl?: string
  method: string
  endpointUrl: string
  requestPayload: unknown
  responsePayload: unknown
  rawResponsePayload?: unknown
  parsedResponsePayload?: unknown
  latencyMs: number
  tokenCount?: number
  usage?: unknown
  statusCode?: number
  statusText?: string
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

const rateLimitWindowMs = 60_000
const rateLimitMaxRequests = 18
const runtimeState = globalThis as typeof globalThis & {
  socRateLimit?: Map<string, { count: number; resetAt: number }>
}

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

function parseProviderResponse(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return { rawText: text }
  }
}

const sensitiveKeyPattern =
  /^(authorization|cookie|password|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)$/i

function sanitizeForLog(value: unknown, depth = 0): unknown {
  if (depth > 12) return '[MaxDepth]'
  if (Array.isArray(value)) return value.map((item) => sanitizeForLog(item, depth + 1))
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string') {
      return value
        .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]')
        .replace(/([?&](?:api[_-]?key|token|secret)=)[^&\s]+/gi, '$1[REDACTED]')
    }
    return value
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      sensitiveKeyPattern.test(key) ? '[REDACTED]' : sanitizeForLog(entry, depth + 1),
    ]),
  )
}

function makeLlmAuditLog({
  callerAgent,
  provider,
  toolName,
  model,
  baseUrl,
  endpointPath = '/chat/completions',
  requestBody,
  rawResponse,
  rawContent,
  parsedOutput,
  normalizedOutput,
  usage,
  latencyMs,
  statusCode,
  statusText,
  ok,
  errorMessage,
  logType = 'llm',
}: {
  callerAgent: string
  provider: string
  toolName: string
  model: string
  baseUrl: string
  endpointPath?: string
  requestBody: unknown
  rawResponse: unknown
  rawContent?: string
  parsedOutput?: unknown
  normalizedOutput?: unknown
  usage?: unknown
  latencyMs: number
  statusCode?: number
  statusText?: string
  ok: boolean
  errorMessage?: string
  logType?: 'llm' | 'tool'
}) {
  const endpointUrl = `${baseUrl}${endpointPath}`
  const usageRecord = usage && typeof usage === 'object' ? (usage as Record<string, unknown>) : undefined
  return makeLog({
    callerAgent,
    toolName,
    provider,
    model,
    baseUrl,
    method: 'POST',
    endpointUrl,
    requestPayload: sanitizeForLog({
      provider,
      model,
      baseUrl,
      endpointPath,
      endpointUrl,
      method: 'POST',
      body: requestBody,
    }),
    rawResponsePayload: sanitizeForLog(rawResponse),
    parsedResponsePayload: sanitizeForLog(normalizedOutput ?? parsedOutput),
    responsePayload: sanitizeForLog({
      provider,
      model,
      statusCode,
      statusText,
      raw: rawResponse,
      rawContent,
      parsedOutput,
      normalizedOutput: normalizedOutput ?? parsedOutput,
      usage,
      error: errorMessage,
    }),
    latencyMs,
    tokenCount: typeof usageRecord?.total_tokens === 'number' ? usageRecord.total_tokens : undefined,
    usage,
    statusCode,
    statusText,
    status: ok ? 'ok' : 'error',
    type: ok ? logType : 'error',
  })
}

function makeLog(input: Omit<ApiLogEntry, 'id' | 'timestamp'>): ApiLogEntry {
  return { id: crypto.randomUUID(), timestamp: new Date().toISOString(), ...input }
}

function clientKey(req: Request) {
  return (
    req.headers.get('x-nf-client-connection-ip') ??
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
    'anonymous'
  )
}

function rateLimit(req: Request) {
  const now = Date.now()
  const key = clientKey(req)
  const store = (runtimeState.socRateLimit ??= new Map())
  const current = store.get(key)
  if (!current || current.resetAt <= now) {
    store.set(key, { count: 1, resetAt: now + rateLimitWindowMs })
    return undefined
  }
  current.count += 1
  if (current.count > rateLimitMaxRequests) {
    return Response.json(
      { error: 'Rate limit exceeded. Wait before starting another investigation run.' },
      { status: 429, headers: { 'retry-after': `${Math.ceil((current.resetAt - now) / 1000)}` } },
    )
  }
  return undefined
}

function requiredKey() {
  const apiKey = envValue('GLM_API_KEY')
  if (!apiKey) throw new Error('GLM_API_KEY is not configured')
  return apiKey
}

function fireworksKey() {
  return envValue('FIREWORKS_API_KEY')
}

async function callFireworksJson({
  node,
  prompt,
  temperature = 0.72,
  maxTokens = 700,
  send,
}: {
  node: string
  prompt: string
  temperature?: number
  maxTokens?: number
  send: (event: string, data: unknown) => void
}) {
  const apiKey = fireworksKey()
  if (!apiKey) throw new Error('FIREWORKS_API_KEY is not configured')

  const model = envValue('FIREWORKS_MODEL') || 'accounts/fireworks/models/deepseek-v4-pro'
  const baseUrl = envValue('FIREWORKS_BASE_URL') || 'https://api.fireworks.ai/inference/v1'
  const endpointPath = '/chat/completions'
  const requestBody = {
    model,
    temperature,
    max_tokens: maxTokens,
    reasoning_effort: 'none',
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content: 'You are an enterprise SOC graph orchestrator. Return minified valid JSON only.',
      },
      { role: 'user', content: prompt },
    ],
  }
  const started = Date.now()
  let response: Response
  try {
    response = await fetch(`${baseUrl}${endpointPath}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Fireworks request failed before response'
    send('api_call', makeLlmAuditLog({
      callerAgent: node,
      provider: 'fireworks',
      toolName: 'Fireworks',
      model,
      baseUrl,
      endpointPath,
      requestBody,
      rawResponse: null,
      latencyMs: Date.now() - started,
      ok: false,
      errorMessage: message,
    }))
    throw error
  }
  const text = await response.text()
  const parsed = parseProviderResponse(text) as any
  if (!response.ok) {
    send('api_call', makeLlmAuditLog({
      callerAgent: node,
      provider: 'fireworks',
      toolName: 'Fireworks',
      model,
      baseUrl,
      endpointPath,
      requestBody,
      rawResponse: parsed,
      rawContent: text,
      usage: parsed?.usage,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: false,
      errorMessage: `Fireworks ${response.status}: ${text.slice(0, 240)}`,
    }))
    throw new Error(`Fireworks ${response.status}: ${text.slice(0, 240)}`)
  }
  const content = parsed?.choices?.[0]?.message?.content ?? '{}'
  let result: unknown
  try {
    result = extractJson(content)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Fireworks response parse failed'
    send('api_call', makeLlmAuditLog({
      callerAgent: node,
      provider: 'fireworks',
      toolName: 'Fireworks',
      model,
      baseUrl,
      endpointPath,
      requestBody,
      rawResponse: parsed,
      rawContent: content,
      usage: parsed?.usage,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: false,
      errorMessage: message,
    }))
    throw error
  }
  const log = makeLlmAuditLog({
    callerAgent: node,
    provider: 'fireworks',
    toolName: 'Fireworks',
    model,
    baseUrl,
    endpointPath,
    requestBody,
    rawResponse: parsed,
    rawContent: content,
    parsedOutput: result,
    normalizedOutput: result,
    usage: parsed?.usage,
    latencyMs: Date.now() - started,
    statusCode: response.status,
    statusText: response.statusText,
    ok: true,
  })
  send('api_call', log)
  return { result, log }
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
  const endpointPath = '/chat/completions'
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
  let response: Response
  try {
    response = await fetch(`${baseUrl}${endpointPath}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
        'accept-language': 'en-US,en',
      },
      body: JSON.stringify(body),
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'GLM request failed before response'
    send('api_call', makeLlmAuditLog({
      callerAgent: node,
      provider: 'z.ai',
      toolName: 'GLM-5.1',
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: null,
      latencyMs: Date.now() - started,
      ok: false,
      errorMessage: message,
    }))
    throw error
  }

  if (!streamDeltas) {
    const text = await response.text()
    const parsed = parseProviderResponse(text) as any
    if (!response.ok) {
      send('api_call', makeLlmAuditLog({
        callerAgent: node,
        provider: 'z.ai',
        toolName: 'GLM-5.1',
        model,
        baseUrl,
        endpointPath,
        requestBody: body,
        rawResponse: parsed,
        rawContent: text,
        usage: parsed?.usage,
        latencyMs: Date.now() - started,
        statusCode: response.status,
        statusText: response.statusText,
        ok: false,
        errorMessage: `GLM ${response.status}: ${text.slice(0, 240)}`,
      }))
      throw new Error(`GLM ${response.status}: ${text.slice(0, 240)}`)
    }
    const content = parsed?.choices?.[0]?.message?.content ?? '{}'
    let result: unknown
    try {
      result = extractJson(content)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'GLM response parse failed'
      send('api_call', makeLlmAuditLog({
        callerAgent: node,
        provider: 'z.ai',
        toolName: 'GLM-5.1',
        model,
        baseUrl,
        endpointPath,
        requestBody: body,
        rawResponse: parsed,
        rawContent: content,
        usage: parsed?.usage,
        latencyMs: Date.now() - started,
        statusCode: response.status,
        statusText: response.statusText,
        ok: false,
        errorMessage: message,
      }))
      throw error
    }
    const log = makeLlmAuditLog({
      callerAgent: node,
      provider: 'z.ai',
      toolName: 'GLM-5.1',
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: parsed,
      rawContent: content,
      parsedOutput: result,
      normalizedOutput: result,
      usage: parsed?.usage,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: true,
    })
    send('api_call', log)
    return { result, log }
  }

  if (!response.ok || !response.body) {
    const text = await response.text().catch(() => '')
    send('api_call', makeLlmAuditLog({
      callerAgent: node,
      provider: 'z.ai',
      toolName: 'GLM-5.1',
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: parseProviderResponse(text),
      rawContent: text,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: false,
      errorMessage: `GLM stream failed ${response.status}: ${text.slice(0, 240)}`,
    }))
    throw new Error(`GLM stream failed ${response.status}: ${text.slice(0, 240)}`)
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let content = ''
  let usage: any = undefined
  const rawChunks: unknown[] = []
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
      rawChunks.push(chunk)
      usage = chunk?.usage ?? usage
      const delta = chunk?.choices?.[0]?.delta?.content ?? ''
      if (delta) {
        content += delta
        send('delta', { node, content: delta })
      }
    }
  }
  let result: unknown
  try {
    result = extractJson(content)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'GLM stream response parse failed'
    send('api_call', makeLlmAuditLog({
      callerAgent: node,
      provider: 'z.ai',
      toolName: 'GLM-5.1',
      model,
      baseUrl,
      endpointPath,
      requestBody: body,
      rawResponse: { chunks: rawChunks },
      rawContent: content,
      usage,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: false,
      errorMessage: message,
    }))
    throw error
  }
  const log = makeLlmAuditLog({
    callerAgent: node,
    provider: 'z.ai',
    toolName: 'GLM-5.1',
    model,
    baseUrl,
    endpointPath,
    requestBody: body,
    rawResponse: { chunks: rawChunks },
    rawContent: content,
    parsedOutput: result,
    normalizedOutput: result,
    usage,
    latencyMs: Date.now() - started,
    statusCode: response.status,
    statusText: response.statusText,
    ok: true,
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

function toolSystemPrompt(tool: (typeof toolEndpoints)[number]) {
  return (
    `You are ${tool.name}, a corporate security tool API used during SOC incident response. ` +
    'Return compact valid JSON only. Do not use markdown. Include the requested indicators and incident ID in the response. ' +
    'Make the response realistic, tool-specific, and different on every run.'
  )
}

function toolUserPrompt(tool: (typeof toolEndpoints)[number], incident: any, state: any) {
  return JSON.stringify({
    tool: tool.name,
    logicalEndpoint: tool.endpoint,
    callerAgent: tool.agent,
    task: 'Generate a realistic enterprise tool API response for this incident investigation.',
    request: buildToolRequest(tool, incident, state),
    responseContract: {
      verdict: 'short security verdict',
      evidence: 'one sentence with IOC and affected host/user',
      confidence: 'number from 0 to 1',
      records: '2-4 concise tool-specific findings',
      recommendedNextStep: 'one sentence',
    },
    diversitySeed: `${incident?.incidentId ?? 'incident'}-${tool.name}-${Date.now()}-${crypto.randomUUID()}`,
  })
}

async function callToolLlm(
  tool: (typeof toolEndpoints)[number],
  incident: any,
  state: any,
): Promise<{ tool: (typeof toolEndpoints)[number]; body: any; log: ApiLogEntry }> {
  const provider = 'z.ai'
  const apiKey = requiredKey()
  const model = envValue('GLM_TOOL_MODEL') || 'glm-5-turbo'
  const baseUrl = envValue('GLM_BASE_URL') || 'https://api.z.ai/api/coding/paas/v4'
  const endpointPath = '/chat/completions'
  const requestBody = {
    model,
    thinking: { type: 'disabled' },
    temperature: 0.76,
    max_tokens: 260,
    stream: false,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: toolSystemPrompt(tool) },
      { role: 'user', content: toolUserPrompt(tool, incident, state) },
    ],
  }
  const started = Date.now()
  let response: Response
  try {
    response = await fetch(`${baseUrl}${endpointPath}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
        'accept-language': 'en-US,en',
      },
      body: JSON.stringify(requestBody),
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : `${tool.name} model request failed before response`
    const log = makeLlmAuditLog({
      callerAgent: tool.agent,
      provider,
      toolName: tool.name,
      model,
      baseUrl,
      endpointPath,
      requestBody,
      rawResponse: null,
      latencyMs: Date.now() - started,
      ok: false,
      errorMessage: message,
      logType: 'tool',
    })
    return { tool, body: { tool: tool.name, endpoint: tool.endpoint, error: message }, log }
  }

  const text = await response.text()
  const parsed = parseProviderResponse(text) as any
  const content = parsed?.choices?.[0]?.message?.content ?? '{}'
  let result: unknown
  let ok = response.ok
  let errorMessage: string | undefined
  if (!response.ok) {
    errorMessage = `${tool.name} provider ${response.status}: ${text.slice(0, 240)}`
    result = { error: errorMessage }
    ok = false
  } else {
    try {
      result = extractJson(content)
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : `${tool.name} response parse failed`
      result = { error: errorMessage, rawContent: content }
      ok = false
    }
  }

  const body = {
    tool: tool.name,
    endpoint: tool.endpoint,
    generatedAt: new Date().toISOString(),
    incidentId: incident?.incidentId,
    provider,
    model,
    usage: parsed?.usage,
    data: result,
  }
  const log = makeLlmAuditLog({
    callerAgent: tool.agent,
    provider,
    toolName: tool.name,
    model,
    baseUrl,
    endpointPath,
    requestBody,
    rawResponse: parsed,
    rawContent: content,
    parsedOutput: result,
    normalizedOutput: body,
    usage: parsed?.usage,
    latencyMs: Date.now() - started,
    statusCode: response.status,
    statusText: response.statusText,
    ok,
    errorMessage,
    logType: 'tool',
  })
  return { tool, body, log }
}

function normalizeRunPlan(raw: any) {
  const compactIncident = raw?.incident ?? raw?.i ?? {}
  const severityOptions = ['Critical', 'High', 'Medium', 'Low']
  const severity = severityOptions.includes(compactIncident.severity) ? compactIncident.severity : 'High'
  const iocs = compactIncident.iocs ?? {}
  const incident = {
    incidentId: compactIncident.incidentId ?? `SOC-${new Date().toISOString().slice(0, 10).replaceAll('-', '')}-${crypto.randomUUID().slice(0, 6)}`,
    timestamp: compactIncident.timestamp ?? new Date().toISOString(),
    severity,
    priorityScore: Number(compactIncident.priorityScore ?? 8),
    incidentType: compactIncident.incidentType ?? 'lateral movement',
    affectedUser: compactIncident.affectedUser ?? 'jsmith@corp.example',
    affectedHost: compactIncident.affectedHost ?? 'WS-FIN-042',
    affectedIp: compactIncident.affectedIp ?? iocs.ip ?? '10.42.18.77',
    affectedDepartment: compactIncident.affectedDepartment ?? 'Finance',
    mitreTactic: compactIncident.mitreTactic ?? 'Credential Access',
    mitreTechnique: compactIncident.mitreTechnique ?? 'T1003 OS Credential Dumping',
    initialAlertSource: compactIncident.initialAlertSource ?? 'EDR',
    iocs: {
      ip: iocs.ip ?? compactIncident.affectedIp ?? '10.42.18.77',
      hash: iocs.hash ?? 'b8a9f4f9d3a7d827b7110edc9d0f42d9b30d0db1f7c4e75db3ef1be9013c8a33',
      domain: iocs.domain ?? 'cdn-update-check.example',
      url: iocs.url ?? 'https://cdn-update-check.example/a.gif',
    },
    rawLogSnippet:
      compactIncident.rawLogSnippet ??
      `${new Date().toISOString()} EDR alert ${compactIncident.affectedHost ?? 'WS-FIN-042'} suspicious credential access`,
  }

  const compactSupervisor = raw?.supervisor ?? raw?.s ?? {}
  const supervisor = {
    route: compactSupervisor.route ?? compactSupervisor.r ?? 'containment',
    rationale: compactSupervisor.rationale ?? compactSupervisor.why ?? 'Correlated identity and endpoint signals support containment.',
    selectedAgents: compactSupervisor.selectedAgents ?? compactSupervisor.agents ?? ['Triage', 'Enrichment', 'Identity', 'Endpoint', 'Logs'],
    confidence: Number(compactSupervisor.confidence ?? compactSupervisor.conf ?? 0.88),
  }

  const compactTriage = raw?.triage ?? raw?.t ?? {}
  const triage = {
    classification: compactTriage.classification ?? compactTriage.class ?? 'Confirmed malicious activity',
    dedupeStatus: compactTriage.dedupeStatus ?? compactTriage.dedupe ?? 'new',
    riskScore: Number(compactTriage.riskScore ?? compactTriage.risk ?? 86),
    keyFindings: compactTriage.keyFindings ?? compactTriage.findings ?? ['IOC and host activity are correlated'],
  }

  const compactTools = Array.isArray(raw?.toolResults) ? raw.toolResults : Array.isArray(raw?.v) ? raw.v : []
  const toolResults = toolEndpoints.map((tool, index) => {
    const item = compactTools[index] ?? {}
    const evidence = item?.responsePayload?.evidence ?? item?.e ?? `${incident.iocs.ip} observed on ${incident.affectedHost}`
    return {
      name: item.name ?? item.n ?? tool.name,
      endpoint: item.endpoint ?? item.p ?? tool.endpoint,
      responsePayload: item.responsePayload ?? {
        verdict: item.verdict ?? item.r ?? `${tool.name} found suspicious correlation`,
        evidence,
      },
      confidence: Number(item.confidence ?? item.c ?? 0.82),
      tokenCount: item.tokenCount,
    }
  })

  const compactContainment = raw?.containment ?? raw?.a ?? {}
  const containment = {
    actionName: compactContainment.actionName ?? compactContainment.action ?? 'isolate_host',
    target: compactContainment.target ?? incident.affectedHost,
    toolArguments: compactContainment.toolArguments ?? compactContainment.args ?? {
      host: incident.affectedHost,
      durationMinutes: 45,
      ticket: incident.incidentId,
    },
    riskJustification:
      compactContainment.riskJustification ??
      compactContainment.risk ??
      'Temporary isolation may interrupt user work but reduces lateral movement risk.',
  }

  return { incident, supervisor, triage, toolResults, containment }
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
  const limited = rateLimit(req)
  if (limited) return limited

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
        const orchestrationPrompt = `Return minified JSON only. Seed ${Date.now()}-${crypto.randomUUID()}. Shape {"i":incident,"a":approval}. i must include incidentId,timestamp,severity,priorityScore,incidentType,affectedUser,affectedHost,affectedIp,affectedDepartment,mitreTactic,mitreTechnique,initialAlertSource,iocs{ip,hash,domain,url},rawLogSnippet(one line). a={actionName,target,toolArguments,riskJustification}. Keep text short.`
        let orchestratedRun
        try {
          orchestratedRun = await callGlmJson({
            node: 'Supervisor Graph Orchestrator',
            prompt: orchestrationPrompt,
            temperature: 0.9,
            maxTokens: 420,
            send,
            streamDeltas: false,
            modelName: envValue('GLM_TOOL_MODEL') || 'glm-5-turbo',
          })
        } catch (error) {
          if (!fireworksKey()) throw error
          const message = error instanceof Error ? error.message : 'Z.ai orchestration failed'
          timeline('Z.ai fallback', `Falling back to Fireworks only because Z.ai failed: ${message}`, 'warning', send)
          orchestratedRun = await callFireworksJson({
            node: 'Supervisor Graph Orchestrator',
            prompt: orchestrationPrompt,
            temperature: 0.82,
            maxTokens: 420,
            send,
          })
        }
        const streamPreview = JSON.stringify(orchestratedRun.result)
        for (let index = 0; index < streamPreview.length; index += 96) {
          send('delta', {
            node: 'Supervisor Graph Orchestrator',
            content: streamPreview.slice(index, index + 96),
          })
        }
        const runPlan = normalizeRunPlan(orchestratedRun.result)
        const incident = runPlan.incident
        const supervisorResult = runPlan.supervisor ?? {}
        const triageResult = runPlan.triage ?? {}
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
          'Enrichment, identity, endpoint, log, cloud, and ticketing tools are calling real LLM-backed APIs in a Send() fan-out.',
          'info',
          send,
        )
        for (const node of ['enrichment', 'identity', 'endpoint', 'log_analysis', 'threat_intel']) {
          send('node_start', { node, timestamp: new Date().toISOString() })
        }
        const toolResults = await Promise.all(
          toolEndpoints.map(async (tool) => {
            const result = await callToolLlm(tool, incident, state)
            send('api_call', result.log)
            return result
          }),
        )
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
