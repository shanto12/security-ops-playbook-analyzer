/** Normalize model-produced argument envelopes; analyst edits are validated separately. */
export function asArgumentsObject(value: unknown, fallback: Record<string, unknown> = {}): Record<string, unknown> {
  let parsed = value
  for (let depth = 0; depth < 2 && typeof parsed === 'string'; depth += 1) {
    try { parsed = JSON.parse(parsed) } catch { return fallback }
  }
  return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
    ? parsed as Record<string, unknown>
    : fallback
}
