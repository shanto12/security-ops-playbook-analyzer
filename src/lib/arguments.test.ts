import { describe, expect, it } from 'vitest'
import { asArgumentsObject } from './arguments'

describe('Model argument normalization', () => {
  it('decodes the JSON string emitted by the production model into editable fields', () => {
    expect(asArgumentsObject('{"host":"WKS-FIN-4471","durationMinutes":45}')).toEqual({ host: 'WKS-FIN-4471', durationMinutes: 45 })
  })
  it('retains valid objects and rejects non-object model envelopes', () => {
    expect(asArgumentsObject({ target: 'synthetic-user' })).toEqual({ target: 'synthetic-user' })
    for (const invalid of ['bad JSON', 'null', '[]', 42, undefined]) expect(asArgumentsObject(invalid, { host: 'fallback' })).toEqual({ host: 'fallback' })
  })
})
