import type { SseEvent } from './types'

export function parseSseFrames(buffer: string): { events: SseEvent[]; remainder: string } {
  const chunks = buffer.split(/\n\n/)
  const remainder = chunks.pop() ?? ''
  const events: SseEvent[] = []

  for (const chunk of chunks) {
    const lines = chunk.split(/\n/).filter(Boolean)
    let event = 'message'
    const dataLines: string[] = []

    for (const line of lines) {
      if (line.startsWith(':')) continue
      if (line.startsWith('event:')) event = line.slice(6).trim()
      if (line.startsWith('data:')) dataLines.push(line.slice(5).trim())
    }

    if (dataLines.length === 0) {
      events.push({ event, data: {} })
      continue
    }

    const dataText = dataLines.join('\n')
    try {
      events.push({ event, data: JSON.parse(dataText) })
    } catch {
      events.push({ event, data: dataText })
    }
  }

  return { events, remainder }
}

export async function consumeSse(
  response: Response,
  onEvent: (event: SseEvent) => void,
): Promise<void> {
  if (!response.ok) {
    const text = await response.text().catch(() => '')
    throw new Error(text || `Request failed with ${response.status}`)
  }
  if (!response.body) throw new Error('SSE response did not include a body')

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const parsed = parseSseFrames(buffer)
    buffer = parsed.remainder
    parsed.events.forEach(onEvent)
  }

  buffer += decoder.decode()
  const parsed = parseSseFrames(buffer + '\n\n')
  parsed.events.forEach(onEvent)
}

export function createMockSseResponse(events: SseEvent[]): Response {
  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    start(controller) {
      for (const item of events) {
        controller.enqueue(
          encoder.encode(`event: ${item.event}\ndata: ${JSON.stringify(item.data)}\n\n`),
        )
      }
      controller.close()
    },
  })
  return new Response(stream, {
    headers: { 'content-type': 'text/event-stream' },
  })
}
