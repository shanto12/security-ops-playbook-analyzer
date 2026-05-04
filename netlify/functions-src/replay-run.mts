import type { Config } from '@netlify/functions'

function envValue(name: string): string | undefined {
  const netlify = (globalThis as any).Netlify
  return netlify?.env?.get?.(name) ?? process.env[name]
}

function extractJson(text: string): any {
  try {
    return JSON.parse(text.trim())
  } catch {
    const match = text.match(/\{[\s\S]*\}/)
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
    if (typeof value === 'string') return value.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]')
    return value
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      sensitiveKeyPattern.test(key) ? '[REDACTED]' : sanitizeForLog(entry, depth + 1),
    ]),
  )
}

export default async (req: Request) => {
  if (req.method !== 'POST') return Response.json({ error: 'Method not allowed' }, { status: 405 })
  let body: any
  try {
    body = await req.json()
  } catch {
    return Response.json({ error: 'Expected JSON body' }, { status: 400 })
  }

  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: unknown) => controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`))
      try {
        const apiKey = envValue('GLM_API_KEY')
        if (!apiKey) throw new Error('GLM_API_KEY is not configured')
        const model = envValue('GLM_MODEL') || 'glm-5.1'
        const baseUrl = envValue('GLM_BASE_URL') || 'https://api.z.ai/api/coding/paas/v4'
        const endpointUrl = `${baseUrl}/chat/completions`
        const requestBody = {
          model,
          thinking: { type: 'disabled' },
          temperature: 0.9,
          max_tokens: 900,
          stream: false,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: 'Return only valid JSON for a LangGraph time-travel fork.' },
            {
              role: 'user',
              content: JSON.stringify({
                checkpoint: body.checkpoint,
                incident: body.incident,
                task:
                  'Replay from this checkpoint and create one alternate branch decision. Show how the route, confidence, and next action differ.',
                returnShape: {
                  branchName: 'string',
                  changedDecision: 'string',
                  reason: 'string',
                  nextAction: 'string',
                  expectedImpact: 'string',
                },
              }),
            },
          ],
        }
        send('node_start', { node: 'supervisor', timestamp: new Date().toISOString() })
        const started = Date.now()
        const emitLlmAudit = ({
          rawResponse,
          rawContent,
          parsedOutput,
          usage,
          latencyMs,
          statusCode,
          statusText,
          ok,
          errorMessage,
        }: {
          rawResponse: unknown
          rawContent?: string
          parsedOutput?: unknown
          usage?: unknown
          latencyMs: number
          statusCode?: number
          statusText?: string
          ok: boolean
          errorMessage?: string
        }) => {
          send('api_call', {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            callerAgent: 'Time Travel Debugger',
            toolName: 'GLM-5.1',
            provider: 'z.ai',
            model,
            baseUrl,
            method: 'POST',
            endpointUrl,
          requestPayload: sanitizeForLog({
            provider: 'z.ai',
            model,
            baseUrl,
              endpointPath: '/chat/completions',
              endpointUrl,
            method: 'POST',
            body: requestBody,
          }),
          rawResponsePayload: sanitizeForLog(parsed),
          parsedResponsePayload: sanitizeForLog(fork),
          responsePayload: sanitizeForLog({
            provider: 'z.ai',
              model,
              statusCode,
              statusText,
              raw: rawResponse,
              rawContent,
              parsedOutput,
              normalizedOutput: parsedOutput,
              usage,
              error: errorMessage,
            }),
            latencyMs,
            tokenCount: usage && typeof usage === 'object' && typeof (usage as Record<string, unknown>).total_tokens === 'number'
              ? (usage as Record<string, number>).total_tokens
              : undefined,
            usage,
            statusCode,
            statusText,
            status: ok ? 'ok' : 'error',
            type: ok ? 'llm' : 'error',
          })
        }
        let response: Response
        try {
          response = await fetch(endpointUrl, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${apiKey}`,
              'content-type': 'application/json',
              'accept-language': 'en-US,en',
            },
            body: JSON.stringify(requestBody),
          })
        } catch (error) {
          const message = error instanceof Error ? error.message : 'GLM request failed before response'
          emitLlmAudit({
            rawResponse: null,
            latencyMs: Date.now() - started,
            ok: false,
            errorMessage: message,
          })
          throw error
        }
        const text = await response.text()
        const parsed = parseProviderResponse(text) as any
        if (!response.ok) {
          emitLlmAudit({
            rawResponse: parsed,
            rawContent: text,
            usage: parsed?.usage,
            latencyMs: Date.now() - started,
            statusCode: response.status,
            statusText: response.statusText,
            ok: false,
            errorMessage: `GLM ${response.status}: ${text.slice(0, 240)}`,
          })
          throw new Error(`GLM ${response.status}: ${text.slice(0, 240)}`)
        }
        const content = parsed?.choices?.[0]?.message?.content ?? '{}'
        let fork: any
        try {
          fork = extractJson(content)
        } catch (error) {
          const message = error instanceof Error ? error.message : 'GLM response parse failed'
          emitLlmAudit({
            rawResponse: parsed,
            rawContent: content,
            usage: parsed?.usage,
            latencyMs: Date.now() - started,
            statusCode: response.status,
            statusText: response.statusText,
            ok: false,
            errorMessage: message,
          })
          throw error
        }
        emitLlmAudit({
          rawResponse: parsed,
          rawContent: content,
          parsedOutput: fork,
          usage: parsed?.usage,
          latencyMs: Date.now() - started,
          statusCode: response.status,
          statusText: response.statusText,
          ok: true,
        })
        send('timeline', {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          title: `Forked ${body.checkpoint?.id}`,
          detail: `${fork.changedDecision}: ${fork.reason}`,
          outcome: 'info',
          durationMs: Date.now() - started,
        })
        send('checkpoint', {
          id: `fork-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`,
          timestamp: new Date().toISOString(),
          node: 'time_travel_fork',
          state: fork,
        })
        send('node_complete', { node: 'supervisor', timestamp: new Date().toISOString(), durationMs: Date.now() - started })
        send('done', {})
      } catch (error) {
        send('error', { message: error instanceof Error ? error.message : 'Replay failed' })
      } finally {
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
  path: '/api/replay-run',
}
