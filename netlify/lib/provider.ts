/** Server-only model configuration. Credentials never appear in audit records. */
export function envValue(name: string): string | undefined {
  return (globalThis as typeof globalThis & { Netlify?: { env: { get: (name: string) => string | undefined } } }).Netlify?.env.get(name)
}

export function getProvider(role: 'primary' | 'tool' = 'primary', requireKey = true) {
  const selected = envValue('AI_PROVIDER') || (envValue('DEEPSEEK_API_KEY') ? 'deepseek' : 'glm')
  if (!['deepseek', 'glm'].includes(selected)) throw new Error('AI_PROVIDER must be deepseek or glm')
  const deepseek = selected === 'deepseek'
  const prefix = deepseek ? 'DEEPSEEK' : 'GLM'
  const apiKey = envValue(`${prefix}_API_KEY`)
  if (requireKey && !apiKey) throw new Error(`${prefix}_API_KEY is not configured`)
  const model = envValue(`${prefix}_${role === 'tool' ? 'TOOL_MODEL' : 'MODEL'}`)
    || envValue(`${prefix}_MODEL`) || (deepseek ? 'deepseek-flash' : role === 'tool' ? 'glm-5-turbo' : 'glm-5.1')
  return {
    id: selected,
    provider: deepseek ? 'DeepSeek' : 'Z.ai',
    toolName: deepseek ? 'DeepSeek' : 'GLM',
    apiKey,
    model,
    baseUrl: (envValue(`${prefix}_BASE_URL`) || (deepseek ? 'https://api.deepseek.com' : 'https://api.z.ai/api/coding/paas/v4')).replace(/\/$/, ''),
  }
}
