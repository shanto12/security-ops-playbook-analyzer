# Threat Model

| Risk | Mitigation |
| --- | --- |
| API key exposure | Key is read server-side from environment variables and is not included in client code. |
| Prompt injection from incident fields | Prompts require compact JSON and tool role boundaries; no real actions are executed. |
| Unsafe containment | Containment pauses for analyst approval and supports reject/edit decisions. |
| Unbounded model runtime | SSE keepalive, compact prompts, JSON mode, and tool model routing keep calls bounded. |
| Public demo data sensitivity | Synthetic data only; no confidential company names or real customer records. |
| Tool response hallucination | UI labels the endpoints as mocked enterprise APIs. API log exposes every generated payload. |
| Replay confusion | Time travel creates a fork checkpoint; original state history remains visible. |
