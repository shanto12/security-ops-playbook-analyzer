// netlify/lib/provider.ts
function envValue(name) {
  return globalThis.Netlify?.env.get(name);
}
function getProvider(role = "primary", requireKey = true) {
  const selected = envValue("AI_PROVIDER") || (envValue("DEEPSEEK_API_KEY") ? "deepseek" : "glm");
  if (!["deepseek", "glm"].includes(selected)) throw new Error("AI_PROVIDER must be deepseek or glm");
  const deepseek = selected === "deepseek";
  const prefix = deepseek ? "DEEPSEEK" : "GLM";
  const apiKey = envValue(`${prefix}_API_KEY`);
  if (requireKey && !apiKey) throw new Error(`${prefix}_API_KEY is not configured`);
  const model = envValue(`${prefix}_${role === "tool" ? "TOOL_MODEL" : "MODEL"}`) || envValue(`${prefix}_MODEL`) || (deepseek ? "deepseek-flash" : role === "tool" ? "glm-5-turbo" : "glm-5.1");
  return {
    id: selected,
    provider: deepseek ? "DeepSeek" : "Z.ai",
    toolName: deepseek ? "DeepSeek" : "GLM",
    apiKey,
    model,
    baseUrl: (envValue(`${prefix}_BASE_URL`) || (deepseek ? "https://api.deepseek.com" : "https://api.z.ai/api/coding/paas/v4")).replace(/\/$/, "")
  };
}

// netlify/functions-src/health.mts
var health_default = async () => {
  const config2 = getProvider("primary", false);
  const toolConfig = getProvider("tool", false);
  let reachable = false;
  let detail = "API key is not configured.";
  if (config2.apiKey) {
    try {
      const response = await fetch(`${config2.baseUrl}/models`, {
        headers: { authorization: `Bearer ${config2.apiKey}` },
        signal: AbortSignal.timeout(7e3)
      });
      const body = await response.json();
      reachable = response.ok && Array.isArray(body.data) && body.data.some((item) => item.id === config2.model);
      detail = reachable ? "Model catalog verified. Generation quota is checked when a run starts." : `Provider unavailable or model not listed (HTTP ${response.status}).`;
    } catch {
      detail = "Provider reachability check failed. Try again shortly.";
    }
  }
  return Response.json({
    service: "soc-ai-agent-demo",
    status: reachable ? "ok" : "degraded",
    mode: reachable ? `live-${config2.id}` : config2.apiKey ? "unavailable" : "missing-key",
    provider: config2.provider,
    model: config2.model,
    toolModel: toolConfig.model,
    orchestrationProvider: config2.provider,
    endpoint: config2.baseUrl,
    healthDetail: detail,
    checkedAt: (/* @__PURE__ */ new Date()).toISOString(),
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
      downloadable_report: true
    },
    models: [config2.model]
  }, { headers: { "cache-control": "no-store" } });
};
var config = { path: "/api/health" };
export {
  config,
  health_default as default
};
