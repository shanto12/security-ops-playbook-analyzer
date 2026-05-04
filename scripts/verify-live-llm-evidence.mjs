import { mkdir, writeFile } from 'node:fs/promises'

const baseUrl = process.argv[2] ?? 'https://security-ops-playbook-analyzer.netlify.app'
const outputPath = process.argv[3] ?? `docs/llm-api-call-proof-${new Date().toISOString().slice(0, 10)}.md`

function hasMessages(value) {
  if (!value || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(hasMessages)
  if (Array.isArray(value.messages) && value.messages.length > 0) return true
  return Object.values(value).some(hasMessages)
}

function hasResponseEvidence(log) {
  return Boolean(
    log?.rawResponsePayload ||
      log?.parsedResponsePayload ||
      log?.responsePayload?.raw ||
      log?.responsePayload?.parsedOutput ||
      log?.responsePayload?.normalizedOutput,
  )
}

function summarizeLog(log) {
  return {
    toolName: log?.toolName,
    type: log?.type,
    provider: log?.provider,
    model: log?.model,
    endpointUrl: log?.endpointUrl,
    status: log?.status,
    statusCode: log?.statusCode,
    latencyMs: log?.latencyMs,
    tokenCount: log?.tokenCount ?? 0,
    hasMessages: hasMessages(log?.requestPayload),
    hasResponseEvidence: hasResponseEvidence(log),
  }
}

function assertLogEvidence(name, log) {
  const summary = summarizeLog(log)
  const failures = []
  if (!summary.status || summary.status !== 'ok') failures.push('status is not ok')
  if (!summary.tokenCount || summary.tokenCount <= 0) failures.push('tokenCount is not greater than zero')
  if (!summary.hasMessages) failures.push('request messages are missing')
  if (!summary.hasResponseEvidence) failures.push('raw/parsed response evidence is missing')
  if (failures.length) {
    throw new Error(`${name} evidence failed: ${failures.join(', ')} :: ${JSON.stringify(summary)}`)
  }
  return summary
}

async function collectSse(path, body, timeoutMs = 90000) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  const started = Date.now()
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: controller.signal,
  }).finally(() => clearTimeout(timer))
  const text = await response.text()
  const events = []
  let event = 'message'
  let data = []
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('event: ')) event = line.slice(7)
    else if (line.startsWith('data: ')) data.push(line.slice(6))
    else if (line === '') {
      if (data.length) {
        try {
          events.push({ event, data: JSON.parse(data.join('\n')) })
        } catch {
          events.push({ event, data: data.join('\n') })
        }
      }
      event = 'message'
      data = []
    }
  }
  return {
    status: response.status,
    ms: Date.now() - started,
    events,
    counts: events.reduce((acc, item) => {
      acc[item.event] = (acc[item.event] ?? 0) + 1
      return acc
    }, {}),
  }
}

function mdTable(rows) {
  const header = '| Call path | Type | Provider | Model | Status | Tokens | Latency | Messages | Response evidence |'
  const separator = '|---|---:|---|---|---|---:|---:|---|---|'
  const body = rows
    .map(
      (row) =>
        `| ${row.path} | ${row.type} | ${row.provider ?? ''} | ${row.model ?? ''} | ${row.statusCode ?? ''} ${row.status ?? ''} | ${row.tokenCount} | ${row.latencyMs}ms | ${row.hasMessages ? 'yes' : 'no'} | ${row.hasResponseEvidence ? 'yes' : 'no'} |`,
    )
    .join('\n')
  return [header, separator, body].join('\n')
}

const startedAt = new Date().toISOString()
const healthResponse = await fetch(`${baseUrl}/api/health`)
const health = await healthResponse.json()
if (!healthResponse.ok || health.status !== 'ok') {
  throw new Error(`Health check failed: ${healthResponse.status} ${JSON.stringify(health)}`)
}

const toolResponse = await fetch(`${baseUrl}/api/jira/issue`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    incidentId: `LIVE-PROOF-${Date.now()}`,
    indicator: 'proof-check.example',
    incident: {
      incidentId: 'LIVE-PROOF',
      iocs: { domain: 'proof-check.example', ip: '203.0.113.77' },
    },
  }),
})
const toolBody = await toolResponse.json()
if (!toolResponse.ok) throw new Error(`Direct tool endpoint failed: ${toolResponse.status} ${JSON.stringify(toolBody)}`)

const agentRun = await collectSse('/api/agent-run', { source: 'llm-proof-script' })
const agentLogs = agentRun.events.filter((item) => item.event === 'api_call').map((item) => item.data)
const supervisorLlm = agentLogs.find((log) => log.type === 'llm')
const toolLogs = agentLogs.filter((log) => log.type === 'tool')
const approval = agentRun.events.find((item) => item.event === 'approval_required')?.data
if (!approval) throw new Error(`agent-run did not produce approval_required: ${JSON.stringify(agentRun.counts)}`)
if (toolLogs.length < 10) throw new Error(`Expected at least 10 real tool model calls, got ${toolLogs.length}`)

const resumeRun = await collectSse('/api/resume-run', {
  decision: 'approve',
  approval,
  editedArguments: approval.toolArguments,
})
const resumeLogs = resumeRun.events.filter((item) => item.event === 'api_call').map((item) => item.data)
const reportLlm = resumeLogs.find((log) => log.type === 'llm')
if (!resumeRun.events.some((item) => item.event === 'report')) {
  throw new Error(`resume-run did not produce a report: ${JSON.stringify(resumeRun.counts)}`)
}

const replayRun = await collectSse('/api/replay-run', {
  threadId: 'llm-proof-script',
  checkpoint: { id: 'ckpt-proof', node: 'supervisor', state: { route: 'containment' } },
  incident: approval.incident,
})
const replayLlm = replayRun.events
  .filter((item) => item.event === 'api_call')
  .map((item) => item.data)
  .find((log) => log.type === 'llm')

const rows = [
  { path: '/api/jira/issue', ...assertLogEvidence('/api/jira/issue llmAudit', toolBody.llmAudit) },
  { path: '/api/agent-run supervisor', ...assertLogEvidence('/api/agent-run supervisor', supervisorLlm) },
  ...toolLogs.map((log) => ({ path: `/api/agent-run ${log.toolName}`, ...assertLogEvidence(`/api/agent-run ${log.toolName}`, log) })),
  { path: '/api/resume-run report', ...assertLogEvidence('/api/resume-run report', reportLlm) },
  { path: '/api/replay-run', ...assertLogEvidence('/api/replay-run', replayLlm) },
]

const totalTokens = rows.reduce((sum, row) => sum + row.tokenCount, 0)
const finishedAt = new Date().toISOString()
const markdown = `# Live LLM API Call Proof

Generated: ${finishedAt}

Base URL: ${baseUrl}

Health:
- Status: ${health.status}
- Mode: ${health.mode}
- Provider: ${health.provider}
- Model: ${health.model}
- Tool model: ${health.toolModel}
- Fireworks model: ${health.fireworksModel}

SSE event counts:
- agent-run: ${JSON.stringify(agentRun.counts)}
- resume-run: ${JSON.stringify(resumeRun.counts)}
- replay-run: ${JSON.stringify(replayRun.counts)}

Result: PASS. Every row below is a real LLM-backed API call with request messages, response evidence, and token usage greater than zero.

Total verified tokens: ${totalTokens}

${mdTable(rows)}

Verification window:
- Started: ${startedAt}
- Finished: ${finishedAt}
`

await mkdir(outputPath.split('/').slice(0, -1).join('/'), { recursive: true })
await writeFile(outputPath, markdown)
console.log(JSON.stringify({ outputPath, rows: rows.length, totalTokens, finishedAt }, null, 2))
