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
        send('node_start', { node: 'supervisor', timestamp: new Date().toISOString() })
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
          }),
        })
        const text = await response.text()
        if (!response.ok) throw new Error(`GLM ${response.status}: ${text.slice(0, 240)}`)
        const parsed = JSON.parse(text)
        const fork = extractJson(parsed?.choices?.[0]?.message?.content ?? '{}')
        send('api_call', {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          callerAgent: 'Time Travel Debugger',
          toolName: 'GLM-5.1',
          method: 'POST',
          endpointUrl: `${baseUrl}/chat/completions`,
          requestPayload: { model, checkpoint: body.checkpoint?.id },
          responsePayload: fork,
          latencyMs: Date.now() - started,
          tokenCount: parsed?.usage?.total_tokens,
          status: 'ok',
          type: 'llm',
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
