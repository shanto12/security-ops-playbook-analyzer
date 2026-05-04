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

function makeLog(input: any) {
  return { id: crypto.randomUUID(), timestamp: new Date().toISOString(), ...input }
}

function makeLlmAuditLog({
  callerAgent,
  provider,
  toolName,
  model,
  baseUrl,
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
}: {
  callerAgent: string
  provider: string
  toolName: string
  model: string
  baseUrl: string
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
}) {
  const endpointUrl = `${baseUrl}/chat/completions`
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
      endpointPath: '/chat/completions',
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
    type: ok ? 'llm' : 'error',
  })
}

function reportText(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed || /no report entries captured/i.test(trimmed)) return undefined
    return trimmed
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (!value || typeof value !== 'object') return undefined
  const record = value as Record<string, any>
  if (record.title || record.detail) {
    return [record.title, record.detail, record.outcome ? `[${record.outcome}]` : undefined]
      .filter(Boolean)
      .map(String)
      .join(': ')
  }
  if (record.toolName) {
    const tokens = typeof record.tokenCount === 'number' ? ` (${record.tokenCount} tokens)` : ''
    return `${record.toolName}: ${record.status ?? 'ok'}${tokens}`
  }
  if (record.from && record.to) {
    return `${record.from} -> ${record.to} (${record.kind ?? 'forward'}): ${record.reason ?? record.decision ?? 'routed'}`
  }
  try {
    return JSON.stringify(record)
  } catch {
    return String(record)
  }
}

function firstText(...values: unknown[]) {
  for (const value of values) {
    const text = reportText(value)
    if (text) return text
  }
  return undefined
}

function list(value: unknown, fallback?: unknown, minCount = 1) {
  const parse = (input: unknown) => {
    if (Array.isArray(input)) return input.map(reportText).filter((item): item is string => Boolean(item))
    const text = reportText(input)
    return text ? [text] : []
  }
  const primary = parse(value)
  if (primary.length >= minCount) return primary
  const merged = [
    ...primary,
    ...parse(fallback).filter((item) => !primary.some((existing) => existing === item)),
  ]
  return merged
}

function normalizeReport(report: any, incident: any, decision: string, fallback: any = {}) {
  const defaultSummary = `Investigation for ${incident?.incidentId ?? 'the incident'} completed with analyst decision ${decision}.`
  const defaultRootCause = 'Root cause requires follow-up validation from endpoint and identity teams.'
  return {
    executiveSummary: firstText(report?.executiveSummary, fallback?.executiveSummary, defaultSummary) ?? defaultSummary,
    rootCause: firstText(report?.rootCause, fallback?.rootCause, defaultRootCause) ?? defaultRootCause,
    mitreMapping: list(report?.mitreMapping, fallback?.mitreMapping, 2),
    timeline: list(report?.timeline, fallback?.timeline, 4),
    agentRouting: list(report?.agentRouting ?? report?.cycleSummary ?? report?.routingTrace, fallback?.agentRouting),
    containmentActions: list(report?.containmentActions, fallback?.containmentActions, 2),
    recommendations: list(report?.recommendations, fallback?.recommendations, 4),
    analystDecisions: list(report?.analystDecisions, fallback?.analystDecisions),
    toolResultSummary: list(report?.toolResultSummary, fallback?.toolResultSummary, 2),
  }
}

function summarizeTimeline(value: unknown) {
  if (!Array.isArray(value)) return []
  return value.map(reportText).filter((item): item is string => Boolean(item))
}

function formatToolEvidence(log: Record<string, any>) {
  const tokens = typeof log.tokenCount === 'number' ? `, ${log.tokenCount} tokens` : ''
  const latency = typeof log.latencyMs === 'number' ? `, ${Math.round(log.latencyMs)}ms` : ''
  return `${log.toolName}: ${log.status ?? 'ok'} via ${log.callerAgent ?? 'unknown agent'}${tokens}${latency}`
}

function summarizeApiLogs(value: unknown) {
  if (!Array.isArray(value)) return []
  return value
    .filter((log) => log && typeof log === 'object')
    .map((log) => {
      const record = log as Record<string, any>
      const payload = record.parsedResponsePayload ?? record.responsePayload
      return {
        type: record.type,
        toolName: record.toolName,
        callerAgent: record.callerAgent,
        endpointUrl: record.endpointUrl,
        status: record.status,
        latencyMs: record.latencyMs,
        tokenCount: record.tokenCount,
        result: payload,
      }
    })
    .filter((log) => log.toolName)
    .slice(0, 18)
}

function summarizeRoutes(value: unknown) {
  if (!Array.isArray(value)) return []
  return value
    .filter((route) => route && typeof route === 'object')
    .map((route) => {
      const record = route as Record<string, any>
      return {
        from: record.from,
        to: record.to,
        kind: record.kind,
        decision: record.decision,
        reason: record.reason,
        checkpointId: record.checkpointId,
      }
    })
    .filter((route) => route.from && route.to)
}

function formatRoutes(routes: Array<Record<string, any>>) {
  return routes.map((route) => {
    const edge = `${String(route.from).replaceAll('_', ' ')} -> ${String(route.to).replaceAll('_', ' ')}`
    return `${edge} (${route.kind ?? 'forward'}): ${route.reason ?? route.decision ?? 'routed'}`
  })
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

async function modelReport(prompt: unknown, send: (event: string, data: unknown) => void) {
  const useGlm = Boolean(envValue('GLM_API_KEY'))
  const apiKey = useGlm ? envValue('GLM_API_KEY') : envValue('FIREWORKS_API_KEY')
  if (!apiKey) throw new Error('No report model API key is configured')
  const provider = useGlm ? 'z.ai' : 'fireworks'
  const toolName = useGlm ? 'GLM-5.1' : 'Fireworks'
  const model = useGlm
    ? envValue('GLM_MODEL') || 'glm-5.1'
    : envValue('FIREWORKS_MODEL') || 'accounts/fireworks/models/deepseek-v4-pro'
  const baseUrl = useGlm
    ? envValue('GLM_BASE_URL') || 'https://api.z.ai/api/coding/paas/v4'
    : envValue('FIREWORKS_BASE_URL') || 'https://api.fireworks.ai/inference/v1'
  const requestBody = {
    model,
    temperature: 0.72,
    max_tokens: 620,
    ...(useGlm ? { thinking: { type: 'disabled' } } : { reasoning_effort: 'none' }),
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content: 'Return compact valid JSON only for a SOC incident report. No markdown.',
      },
      { role: 'user', content: JSON.stringify(prompt) },
    ],
  }
  const started = Date.now()
  let response: Response
  try {
    response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${apiKey}`,
        'content-type': 'application/json',
        ...(useGlm ? { 'accept-language': 'en-US,en' } : {}),
      },
      body: JSON.stringify(requestBody),
    })
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Report model request failed'
    send('api_call', makeLlmAuditLog({
      callerAgent: 'Reporting Agent',
      provider,
      toolName,
      model,
      baseUrl,
      requestBody,
      rawResponse: null,
      rawContent: '',
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
      callerAgent: 'Reporting Agent',
      provider,
      toolName,
      model,
      baseUrl,
      requestBody,
      rawResponse: parsed,
      rawContent: text,
      usage: parsed?.usage,
      latencyMs: Date.now() - started,
      statusCode: response.status,
      statusText: response.statusText,
      ok: false,
      errorMessage: `${toolName} ${response.status}: ${text.slice(0, 220)}`,
    }))
    throw new Error(`${toolName} ${response.status}: ${text.slice(0, 220)}`)
  }
  const content = parsed?.choices?.[0]?.message?.content ?? '{}'
  let report: any
  try {
    report = extractJson(content)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Report model parse failed'
    send('api_call', makeLlmAuditLog({
      callerAgent: 'Reporting Agent',
      provider,
      toolName,
      model,
      baseUrl,
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
  send('api_call', makeLlmAuditLog({
    callerAgent: 'Reporting Agent',
    provider,
    toolName,
    model,
    baseUrl,
    requestBody,
    rawResponse: parsed,
    rawContent: content,
    parsedOutput: report,
    normalizedOutput: report,
    usage: parsed?.usage,
    latencyMs: Date.now() - started,
    statusCode: response.status,
    statusText: response.statusText,
    ok: true,
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
        checkpoint('containment_resume', { decision, containmentLogs: logs.map((log) => log.responsePayload) }, send)
        send('node_complete', { node: 'containment', timestamp: new Date().toISOString(), durationMs: Date.now() - startMs })

        for (const node of ['ticketing', 'notification', 'reporting']) {
          send('node_start', { node, timestamp: new Date().toISOString() })
        }
        const ticketPayload = { incident, decision, approval: payload.approval, action: 'post_resume_update' }
        const priorToolResults = summarizeApiLogs(payload?.apiLogs)
        const routingTrace = summarizeRoutes(payload?.routes)
        const formattedRoutes = formatRoutes(routingTrace)
        const timelineSummary = summarizeTimeline(payload?.timeline)
        const enterpriseToolEvidence = priorToolResults.filter(
          (log) =>
            log.toolName &&
            !['Agent Route', 'Cyclic Agent Route', 'Human Approval'].includes(String(log.toolName)),
        )
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
        send('node_complete', { node: 'ticketing', timestamp: new Date().toISOString(), durationMs: 0 })
        send('node_complete', { node: 'notification', timestamp: new Date().toISOString(), durationMs: 0 })

        const fallbackReport = {
            executiveSummary: `${incident?.severity ?? 'High'} ${incident?.incidentType ?? 'security'} incident ${incident?.incidentId ?? ''} completed the cyclic LangGraph investigation with analyst decision ${decision}.`,
            rootCause: `Correlated identity, endpoint, log, and threat intelligence evidence points to ${incident?.incidentType ?? 'malicious activity'} involving ${incident?.affectedUser ?? 'the affected user'} on ${incident?.affectedHost ?? 'the affected host'} with IOC ${incident?.iocs?.ip ?? incident?.iocs?.domain ?? incident?.affectedIp ?? 'unknown'}.`,
            mitreMapping: [incident?.mitreTactic, incident?.mitreTechnique].filter(Boolean),
            timeline: timelineSummary.length ? timelineSummary : [
              'Incident generated and routed by supervisor',
              'Cyclic StateGraph route loop completed',
              'Parallel enrichment and investigation completed',
              `Analyst decision recorded: ${decision}`,
              'Ticketing and notifications completed',
            ],
            agentRouting: formattedRoutes.length ? formattedRoutes : ['Supervisor -> Triage -> Enrichment -> Log Analysis -> Enrichment -> Threat Intel -> Supervisor -> Containment'],
            containmentActions: logs.length
              ? logs.map((log) => `${log.toolName}: ${JSON.stringify(log.responsePayload)}`)
              : [`No containment tool was executed because analyst decision was ${decision}.`],
            recommendations: [
              `Terminate active sessions and rotate credentials for ${incident?.affectedUser ?? 'the affected user'}.`,
              `Review process ancestry and network connections on ${incident?.affectedHost ?? 'the affected host'}.`,
              `Hunt for ${incident?.iocs?.domain ?? incident?.iocs?.ip ?? 'incident IOCs'} across SIEM, Microsoft 365, and cloud logs.`,
              'Validate containment expiry, ticket ownership, and post-incident control improvements before closure.',
            ],
            analystDecisions: [
              `${decision} ${payload?.approval?.actionName ?? 'containment'} for ${payload?.approval?.target ?? incident?.affectedHost ?? 'the target'} with arguments ${JSON.stringify(payload?.editedArguments ?? payload?.approval?.toolArguments ?? {})}`,
            ],
            toolResultSummary: [
              ...enterpriseToolEvidence.map(formatToolEvidence),
              ...ticketLogs.map((log) => `${log.toolName}: ok`),
            ],
          }
        let rawReport = fallbackReport
        try {
          rawReport = await modelReport(
            {
              incident,
              decision,
              approval: payload.approval,
              containmentResults: logs.map((log) => log.responsePayload),
              ticketingResults: ticketLogs.map((log) => log.responsePayload),
              priorToolResults,
              routingTrace,
              cycleSummary: formattedRoutes,
              requiredShape: {
                executiveSummary: 'one sentence',
                rootCause: 'one sentence',
                mitreMapping: ['strings'],
                timeline: ['at least five non-empty strings'],
                agentRouting: ['summarize each cyclic agent handoff, including backtrack edges'],
                containmentActions: ['at least two non-empty strings'],
                recommendations: ['at least four non-empty strings'],
                analystDecisions: ['at least one non-empty string'],
                toolResultSummary: ['summarize each prior enterprise tool plus ticketing/notification result as non-empty strings'],
              },
            },
            send,
          )
        } catch {
          rawReport = fallbackReport
        }
        const report = normalizeReport(rawReport, incident, decision, fallbackReport)
        if (report.agentRouting.length === 0) {
          report.agentRouting = formattedRoutes.length
            ? formattedRoutes
            : ['Supervisor -> Triage -> Enrichment -> Log Analysis -> Enrichment -> Threat Intel -> Supervisor -> Containment']
        }
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
        send('done', {})
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
