import type { Config } from '@netlify/functions'
import { getProvider } from '../lib/provider'

export default async () => {
  const config = getProvider('primary', false)
  const toolConfig = getProvider('tool', false)
  let reachable = false
  let detail = 'API key is not configured.'
  if (config.apiKey) {
    try {
      // An authenticated metadata probe checks reachability without charging a generation.
      const response = await fetch(`${config.baseUrl}/models`, {
        headers: { authorization: `Bearer ${config.apiKey}` },
        signal: AbortSignal.timeout(7000),
      })
      const body = await response.json() as { data?: { id: string }[] }
      reachable = response.ok && Array.isArray(body.data) && body.data.some((item: { id: string }) => item.id === config.model)
      detail = reachable ? 'Model catalog verified. Generation quota is checked when a run starts.' : `Provider unavailable or model not listed (HTTP ${response.status}).`
    } catch {
      detail = 'Provider reachability check failed. Try again shortly.'
    }
  }
  return Response.json({
    service: 'soc-ai-agent-demo',
    status: reachable ? 'ok' : 'degraded',
    mode: reachable ? `live-${config.id}` : config.apiKey ? 'unavailable' : 'missing-key',
    provider: config.provider,
    model: config.model,
    toolModel: toolConfig.model,
    orchestrationProvider: config.provider,
    endpoint: config.baseUrl,
    healthDetail: detail,
    checkedAt: new Date().toISOString(),
    capabilities: {
      incident_generation: reachable,
      synthetic_tool_responses: reachable,
      real_langgraph_stategraph: true,
      cyclic_back_edges: true,
      sse_streaming: true,
      analyst_approval_continuation: true,
      native_langgraph_interrupt_resume: false,
      snapshot_alternate_analysis: true,
      native_checkpoint_replay: false,
      enterprise_tool_endpoints: false,
      synthetic_tool_endpoints: true,
      api_transparency_log: true,
      downloadable_report: true,
    },
    models: [config.model],
  }, { headers: { 'cache-control': 'no-store' } })
}
export const config: Config = { path: '/api/health' }
