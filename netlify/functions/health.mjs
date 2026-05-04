function envValue(name) {
  const netlify = globalThis.Netlify;
  return netlify?.env?.get?.(name) ?? process.env[name];
}
var health_default = async () => {
  const hasKey = Boolean(envValue("GLM_API_KEY"));
  const model = envValue("GLM_MODEL") || "glm-5.1";
  const toolModel = envValue("GLM_TOOL_MODEL") || "glm-5-turbo";
  const endpoint = envValue("GLM_BASE_URL") || "https://api.z.ai/api/coding/paas/v4";
  return Response.json({
    service: "soc-ai-agent-demo",
    status: hasKey ? "ok" : "degraded",
    mode: hasKey ? "live-glm" : "missing-key",
    provider: "z.ai",
    model,
    toolModel,
    endpoint,
    checkedAt: (/* @__PURE__ */ new Date()).toISOString(),
    capabilities: {
      incident_generation: hasKey,
      glm_tool_responses: hasKey,
      sse_streaming: true,
      hitl_interrupt_resume: true,
      checkpoint_replay: true,
      enterprise_tool_endpoints: true,
      api_transparency_log: true,
      downloadable_report: true
    },
    models: [
      "glm-5.1",
      "glm-5-turbo",
      "glm-5",
      "glm-4.7",
      "glm-4.7-flash",
      "glm-4.7-flashx",
      "glm-4.6",
      "glm-4.5",
      "glm-4.5-air",
      "glm-4.5-x",
      "glm-4.5-airx",
      "glm-4.5-flash",
      "glm-4-32b-0414-128k"
    ]
  });
};
const config = {
  path: "/api/health"
};
export {
  config,
  health_default as default
};
