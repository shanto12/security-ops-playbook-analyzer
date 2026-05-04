import { describe, expect, it } from 'vitest'
import { parseSseFrames } from './sse'

describe('parseSseFrames', () => {
  it('parses named JSON events and keeps the partial frame', () => {
    const parsed = parseSseFrames(
      'event: start\ndata: {"ok":true}\n\nevent: delta\ndata: {"text":"hel',
    )

    expect(parsed.events).toEqual([{ event: 'start', data: { ok: true } }])
    expect(parsed.remainder).toContain('event: delta')
  })
})
