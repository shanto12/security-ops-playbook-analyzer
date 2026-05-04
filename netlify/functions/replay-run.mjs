function envValue(name) {
  const netlify = globalThis.Netlify;
  return netlify?.env?.get?.(name) ?? process.env[name];
}
function extractJson(text) {
  try {
    return JSON.parse(text.trim());
  } catch {
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("GLM response did not include JSON");
    return JSON.parse(match[0]);
  }
}
var replay_run_default = async (req) => {
  let body;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Expected JSON body" }, { status: 400 });
  }
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event, data) => controller.enqueue(encoder.encode(`event: ${event}
data: ${JSON.stringify(data)}

`));
      try {
        const apiKey = envValue("GLM_API_KEY");
        if (!apiKey) throw new Error("GLM_API_KEY is not configured");
        const model = envValue("GLM_MODEL") || "glm-5.1";
        const baseUrl = envValue("GLM_BASE_URL") || "https://api.z.ai/api/coding/paas/v4";
        send("node_start", { node: "supervisor", timestamp: (/* @__PURE__ */ new Date()).toISOString() });
        const started = Date.now();
        const response = await fetch(`${baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            authorization: `Bearer ${apiKey}`,
            "content-type": "application/json",
            "accept-language": "en-US,en"
          },
          body: JSON.stringify({
            model,
            thinking: { type: "disabled" },
            temperature: 0.9,
            max_tokens: 900,
            stream: false,
            response_format: { type: "json_object" },
            messages: [
              { role: "system", content: "Return only valid JSON for a LangGraph time-travel fork." },
              {
                role: "user",
                content: JSON.stringify({
                  checkpoint: body.checkpoint,
                  incident: body.incident,
                  task: "Replay from this checkpoint and create one alternate branch decision. Show how the route, confidence, and next action differ.",
                  returnShape: {
                    branchName: "string",
                    changedDecision: "string",
                    reason: "string",
                    nextAction: "string",
                    expectedImpact: "string"
                  }
                })
              }
            ]
          })
        });
        const text = await response.text();
        if (!response.ok) throw new Error(`GLM ${response.status}: ${text.slice(0, 240)}`);
        const parsed = JSON.parse(text);
        const fork = extractJson(parsed?.choices?.[0]?.message?.content ?? "{}");
        send("api_call", {
          id: crypto.randomUUID(),
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          callerAgent: "Time Travel Debugger",
          toolName: "GLM-5.1",
          method: "POST",
          endpointUrl: `${baseUrl}/chat/completions`,
          requestPayload: { model, checkpoint: body.checkpoint?.id },
          responsePayload: fork,
          latencyMs: Date.now() - started,
          tokenCount: parsed?.usage?.total_tokens,
          status: "ok",
          type: "llm"
        });
        send("timeline", {
          id: crypto.randomUUID(),
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          title: `Forked ${body.checkpoint?.id}`,
          detail: `${fork.changedDecision}: ${fork.reason}`,
          outcome: "info",
          durationMs: Date.now() - started
        });
        send("checkpoint", {
          id: `fork-${Date.now().toString(36)}-${crypto.randomUUID().slice(0, 8)}`,
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          node: "time_travel_fork",
          state: fork
        });
        send("node_complete", { node: "supervisor", timestamp: (/* @__PURE__ */ new Date()).toISOString(), durationMs: Date.now() - started });
        send("done", {});
      } catch (error) {
        send("error", { message: error instanceof Error ? error.message : "Replay failed" });
      } finally {
        controller.close();
      }
    }
  });
  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive"
    }
  });
};
const config = {
  path: "/api/replay-run"
};
export {
  config,
  replay_run_default as default
};
