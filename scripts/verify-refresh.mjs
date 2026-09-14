import assert from 'node:assert/strict'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { chromium } from 'playwright'

// No paid endpoint is reachable without --live. This uses an isolated Chromium
// context, never the user's Chrome profile. Alternate decisions reuse captured
// initial responses, but their resume calls and reports are real production calls.
const live = process.argv.includes('--live')
const capturedInputFile = process.env.VERIFY_INPUT_EVIDENCE
const editOnly = process.env.VERIFY_EDIT_ONLY === '1'
const baseUrl = process.env.VERIFY_URL || 'https://security-ops-playbook-analyzer.netlify.app'
const output = process.env.VERIFY_OUTPUT || '/Users/shanto/Documents/Playground/portfolio-curation-2026-09-14/soc'
const prefix = live ? 'production' : 'read-only'
const localTime = () => new Intl.DateTimeFormat('en-US', { timeZone: 'America/Chicago', dateStyle: 'full', timeStyle: 'long' }).format(new Date())
const evidence = { deploymentId: process.env.VERIFY_DEPLOY_ID, sourceCommit: process.env.VERIFY_COMMIT, baseUrl, mode: live ? editOnly ? 'outstanding live edit decision plus fixture recovery; earlier deployment approve/reject/replay evidence retained separately with explicit provenance' : capturedInputFile ? 'current production decisions with explicitly captured prior production scenario/tool inputs' : 'bounded live production' : 'read-only production', started: localTime(), manualChrome: 'NOT TESTED: parent coordinator owns real Chrome', checks: [], requests: [], errors: [], controls: [], paidRequestCap: editOnly ? 1 : capturedInputFile ? 4 : 15, livePostCount: 0 }
const fixtures = new Map()
const captureTasks = []
let partialWrite = Promise.resolve()
const endpointCalls = new Map()
const editedHost = 'SOC-VERIFY-EDITED-HOST'
const toolPaths = ['/api/virustotal/lookup', '/api/abuseipdb/check', '/api/activedirectory/user', '/api/okta/user-risk', '/api/edr/endpoint', '/api/siem/search', '/api/m365/audit', '/api/cloudtrail/search', '/api/servicenow/ticket', '/api/jira/issue']
await mkdir(output, { recursive: true })
if (capturedInputFile) {
  const prior = JSON.parse(await readFile(capturedInputFile, 'utf8'))
  for (const path of ['/api/agent-run', ...toolPaths]) {
    const response = prior.requests.find(item => item.label === 'desktop-live' && item.path === path && item.status === 200 && item.complete === true)
    assert(response, `Captured successful complete production input is missing: ${path}`)
    fixtures.set(path, { status: response.status, contentType: response.contentType || (path === '/api/agent-run' ? 'text/event-stream' : 'application/json'), body: response.body })
  }
  evidence.initialInputProvenance = { evidenceFile: capturedInputFile, deploymentId: prior.deploymentId, sourceCommit: prior.sourceCommit, capturedAt: prior.finished || prior.started, currentGenerationAndToolApiCalls: 0, note: 'Only initial scenario and ten tool responses are replayed. All analyst resume/report and alternate-analysis calls use the current deployed backend. Function digest comparison and fresh real-Chrome full generation belong to parent coordinator.' }
}
function record(requirement, method, details, status = 'PASS') {
  evidence.checks.push({ requirement, status, method, details })
  console.log(`${status}: ${requirement}`)
}
function sse(text) {
  return text.split(/\r?\n\r?\n/).flatMap(block => {
    const event = block.match(/^event: ?(.+)$/m)?.[1]
    const data = [...block.matchAll(/^data: ?(.*)$/gm)].map(match => match[1]).join('\n')
    if (!event || !data) return []
    return [{ event, data: JSON.parse(data) }]
  })
}
function validateModel(log, label) {
  assert(log, `${label}: missing model audit`)
  assert.equal(log.status, 'ok', `${label}: model call did not succeed`)
  assert(log.tokenCount > 0, `${label}: missing measured token usage`)
  assert(log.rawResponsePayload && log.parsedResponsePayload, `${label}: missing raw/parsed response`)
  assert.equal(log.provider?.toLowerCase(), 'deepseek', `${label}: incorrect provider attribution`)
  assert.equal(log.model, 'deepseek-flash', `${label}: unexpected model`)
  assert(!/glm/i.test(log.toolName), `${label}: DeepSeek incorrectly labeled GLM`)
  return { label, provider: log.provider, model: log.model, tokens: log.tokenCount, latencyMs: log.latencyMs, statusCode: log.statusCode }
}
const browser = await chromium.launch({ headless: true, ...(process.env.VERIFY_BROWSER_EXECUTABLE ? { executablePath: process.env.VERIFY_BROWSER_EXECUTABLE } : {}) })
evidence.browserVersion = browser.version()
async function makePage(label, viewport, reuse = false, injectError = false, retryFixture = false) {
  let failedToolInjected = false
  const context = await browser.newContext({ viewport, acceptDownloads: true, timezoneId: 'America/Chicago', reducedMotion: 'reduce' })
  await context.exposeBinding('__verifyResponse', async (_source, captured) => {
    const { path, body, complete } = captured
    const fixtureInput = reuse && (path === '/api/agent-run' || toolPaths.includes(path))
    const source = retryFixture && fixtureInput ? 'injected tool failure / captured recovery fixture' : fixtureInput ? `captured production input replayed locally (origin deploy ${evidence.initialInputProvenance?.deploymentId || evidence.deploymentId || 'current initial run'})` : injectError ? 'injected error fixture' : 'live production'
    let entry = evidence.requests.find(item => item.label === label && item.captureId === captured.captureId)
    if (!entry) { entry = { label, ...captured, source, captureMethod: 'in-page fetch response clone, same network request' }; evidence.requests.push(entry) }
    else Object.assign(entry, captured)
    if (label === 'desktop-live') fixtures.set(path, { status: captured.status, contentType: captured.contentType, body })
    if (complete) console.log(`RESPONSE: ${label} ${captured.method} ${path} ${captured.status} (${body.length} bytes)`)
    if (captured.captureError) evidence.errors.push({ label, type: 'fetch-clone-capture', path, text: captured.captureError })
    partialWrite = partialWrite.then(() => writeFile(join(output, `${prefix}-evidence.partial.json`), JSON.stringify(evidence, null, 2)))
    captureTasks.push(partialWrite)
  })
  await context.addInitScript(() => {
    const originalFetch = window.fetch.bind(window)
    let captureId = 0
    window.fetch = async (...args) => {
      const response = await originalFetch(...args)
      const request = args[0]
      const path = new URL(typeof request === 'string' || request instanceof URL ? String(request) : request.url, location.href).pathname
      if (path.startsWith('/api/')) {
        const record = { captureId: ++captureId, path, method: args[1]?.method || (request instanceof Request ? request.method : 'GET'), status: response.status, contentType: response.headers.get('content-type'), body: '', complete: false }
        const clone = response.clone()
        void (async () => {
          const reader = clone.body.getReader()
          const decoder = new TextDecoder()
          try {
            for (;;) {
              const { value, done } = await reader.read()
              if (done) break
              record.body += decoder.decode(value, { stream: true })
              await window.__verifyResponse(record)
            }
            record.body += decoder.decode()
            record.complete = true
          } catch (error) { record.captureError = String(error) }
          await window.__verifyResponse(record)
        })()
      }
      return response
    }
  })
  const page = await context.newPage()
  page.on('console', message => { if (message.type() === 'error') evidence.errors.push({ label, type: 'console', text: message.text() }) })
  page.on('pageerror', error => evidence.errors.push({ label, type: 'pageerror', text: error.message }))
  page.on('requestfailed', request => evidence.errors.push({ label, type: 'requestfailed', url: request.url(), text: request.failure()?.errorText }))
  page.on('response', response => {
    const path = new URL(response.url()).pathname
    if (response.status() >= 400) evidence.errors.push({ label, type: 'http', path, status: response.status() })
  })
  await page.route('**/api/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (request.method() !== 'POST') return route.continue()
    if (injectError && path === '/api/agent-run') return route.fulfill({ contentType: 'text/event-stream', body: 'event: error\ndata: {"message":"Verification fixture: provider temporarily unavailable"}\n\nevent: done\ndata: {}\n\n' })
    if (reuse && (path === '/api/agent-run' || toolPaths.includes(path))) {
      const fixture = fixtures.get(path)
      assert(fixture, `Missing captured production fixture: ${path}`)
      if (retryFixture && path === toolPaths[0] && !failedToolInjected) {
        failedToolInjected = true
        const body = JSON.parse(fixture.body)
        body.llmAudit = { ...body.llmAudit, status: 'error', tokenCount: 0, error: 'Verification fixture: synthetic tool unavailable' }
        return route.fulfill({ ...fixture, body: JSON.stringify(body) })
      }
      return route.fulfill(fixture)
    }
    const allowedCount = path === '/api/resume-run' ? 3 : 1
    const current = endpointCalls.get(path) || 0
    if (!live || evidence.livePostCount >= evidence.paidRequestCap || current >= allowedCount || !['/api/agent-run', '/api/resume-run', '/api/replay-run', ...toolPaths].includes(path)) {
      evidence.errors.push({ label, type: 'budget-guard', path, reason: 'No authorized live call allowance remains' })
      return route.fulfill({ status: 429, contentType: 'application/json', body: '{"error":"Verification live-call budget guard"}' })
    }
    endpointCalls.set(path, current + 1)
    evidence.livePostCount += 1
    console.log(`LIVE REQUEST ${evidence.livePostCount}/${evidence.paidRequestCap}: ${label} ${path}`)
    return route.continue()
  })
  await page.goto(baseUrl, { waitUntil: 'networkidle' })
  return page
}
async function screenshot(page, name) {
  const path = join(output, `${prefix}-${name}.png`)
  await page.screenshot({ path, fullPage: true, animations: 'disabled' })
  return path
}
async function layout(page, label) {
  const dimensions = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth }))
  assert(dimensions.document <= dimensions.viewport + 2, `${label}: page overflows viewport ${JSON.stringify(dimensions)}`)
  record(`${label} layout`, 'isolated Playwright', { dimensions, screenshot: await screenshot(page, label) })
}
async function tabs(page, label) {
  const controls = await page.getByRole('tab').all()
  for (const tab of controls) {
    const name = await tab.innerText()
    await tab.click()
    if (await tab.getAttribute('aria-selected') !== null) assert.equal(await tab.getAttribute('aria-selected'), 'true')
    const width = await page.evaluate(() => ({ viewport: innerWidth, document: document.documentElement.scrollWidth }))
    assert(width.document <= width.viewport + 2, `${label} ${name}: horizontal page overflow`)
    evidence.controls.push({ label, type: 'tab', name, result: 'clicked' })
    await screenshot(page, `${label}-tab-${name.toLowerCase().replace(/[^a-z]+/g, '-')}`)
  }
  if (controls.length) {
    await controls[0].click()
    await controls[0].press('End')
    assert.equal(await controls.at(-1).getAttribute('aria-selected'), 'true')
    await controls.at(-1).press('Home')
    assert.equal(await controls[0].getAttribute('aria-selected'), 'true')
  }
}
async function reveal(page, pattern) {
  const tab = page.getByRole('tab', { name: pattern })
  if (await tab.count()) await tab.first().click()
}
async function start(page, onboarding = false) {
  const button = page.getByRole('button', { name: onboarding ? /Start first investigation/i : /Generate Incident|Start investigation|New investigation|Run investigation/i }).first()
  await button.click()
}
async function readyApproval(page, label) {
  const approve = page.getByRole('button', { name: /^Approve$/i })
  await page.waitForFunction(() => document.querySelector('.errorBanner') || [...document.querySelectorAll('button')].some(button => /^Approve$/i.test(button.textContent.trim())), null, { timeout: 90_000 })
  if (await page.locator('.errorBanner').count()) throw new Error(`${label}: ${await page.locator('.errorBanner').innerText()}`)
  const initiallyDisabled = await approve.isDisabled()
  await page.screenshot({ path: join(output, `${prefix}-${label}-active-viewport.png`), fullPage: false })
  await screenshot(page, `${label}-active`)
  await page.waitForFunction(() => document.querySelector('.errorBanner') || [...document.querySelectorAll('button')].some(button => /^Approve$/i.test(button.textContent.trim()) && !button.disabled), null, { timeout: 180_000 })
  if (await page.locator('.errorBanner').count()) throw new Error(`${label}: ${await page.locator('.errorBanner').innerText()}`)
  await Promise.allSettled(captureTasks)
  record(`${label}: analyst approval ready`, 'isolated Playwright + live/captured SSE', { initiallyDisabled, screenshot: await screenshot(page, `${label}-approval`) })
}
async function reportAndExport(page, label) {
  await reveal(page, /report/i)
  const report = page.locator('#final-report')
  await page.waitForFunction(() => document.querySelector('.errorBanner') || [...document.querySelectorAll('#final-report h3')].some(heading => heading.textContent.trim() === 'Executive Summary'), null, { timeout: 90_000 })
  if (await page.locator('.errorBanner').count()) throw new Error(`${label}: ${await page.locator('.errorBanner').innerText()}`)
  await report.getByText('Executive Summary', { exact: true }).waitFor()
  const reportText = await report.innerText()
  for (const title of ['Executive Summary', 'Root Cause', 'MITRE Mapping', 'Investigation Timeline', 'Agent Routing & Cycles', 'Containment Actions', 'Recommendations', 'Analyst Decisions', 'Tool Result Summary']) assert(reportText.includes(title), `Missing report section: ${title}`)
  assert(!reportText.includes('No report entries captured.'), 'Empty report sections')
  const downloadPromise = page.waitForEvent('download')
  await report.getByRole('button', { name: /JSON/i }).click()
  const download = await downloadPromise
  const path = join(output, `${prefix}-${label}-export.json`)
  await download.saveAs(path)
  const exported = JSON.parse(await readFile(path, 'utf8'))
  for (const key of ['mitreMapping', 'timeline', 'agentRouting', 'containmentActions', 'recommendations', 'analystDecisions', 'toolResultSummary']) assert(exported.report[key]?.length > 0, `Empty export field ${key}`)
  await Promise.allSettled(captureTasks)
  const response = evidence.requests.filter(item => item.label === label && item.path === '/api/resume-run').at(-1)
  assert.equal(response?.source, 'live production')
  const events = sse(response.body)
  assert(events.some(item => item.event === 'complete'), 'No backend completion event')
  assert(!events.some(item => item.event === 'error'), 'Backend emitted an error')
  const log = events.find(item => item.event === 'api_call' && item.data.callerAgent === 'Reporting Agent' && item.data.type === 'llm')?.data
  record(`${label}: report and JSON export`, 'isolated Playwright + live production SSE', { audit: validateModel(log, `${label} report`), export: path, screenshot: await screenshot(page, `${label}-report`) })
  await page.screenshot({ path: join(output, `${prefix}-${label}-report-viewport.png`), fullPage: false })
  return exported
}
try {
  const healthResponse = await fetch(`${baseUrl}/api/health`)
  const health = await healthResponse.json()
  assert(healthResponse.ok, `Health HTTP ${healthResponse.status}`)
  evidence.health = health
  record('Health endpoint', 'production API', health)
  const root = await fetch(baseUrl)
  const headers = Object.fromEntries(root.headers)
  for (const name of ['content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'permissions-policy', 'strict-transport-security']) assert(headers[name], `Missing security header ${name}`)
  assert(headers['content-security-policy'].includes("script-src 'self'"))
  record('Production security headers and CSP', 'production HTTP headers', headers)
  for (const path of ['/api/agent-run', '/api/resume-run', '/api/replay-run']) {
    const response = await fetch(`${baseUrl}${path}`)
    assert.equal(response.status, 405, `${path}: GET should reject without paid work`)
  }
  record('API method validation', 'production API; no paid request', 'GET rejected with 405 on all execution endpoints')
  const desktop = await makePage(live ? 'desktop-live' : 'desktop-read-only', { width: 1440, height: 900 }, Boolean(capturedInputFile))
  await layout(desktop, 'desktop-initial')
  await tabs(desktop, 'desktop-initial')
  const brand = desktop.getByRole('link', { name: /Sentinel investigation workspace/i })
  if (await brand.count()) await brand.click()
  const graphShortcut = desktop.getByRole('button', { name: /Inspect the execution graph/i })
  if (await graphShortcut.count()) { await graphShortcut.click(); await reveal(desktop, /overview/i) }
  const runtime = desktop.locator('.systemDetails summary')
  if (await runtime.count()) { await runtime.click(); await runtime.click() }
  const mobile = await makePage('mobile-read-only', { width: 390, height: 844 })
  await layout(mobile, 'mobile-initial')
  await tabs(mobile, 'mobile-initial')
  await mobile.context().close()
  record('Auth and password manager', 'source/UI inventory', 'N/A: public synthetic demo has no account or auth workflow', 'NOT APPLICABLE')
  const errorPage = await makePage('injected-error', { width: 1440, height: 900 }, false, true)
  await start(errorPage, true)
  await errorPage.getByText('Verification fixture: provider temporarily unavailable', { exact: false }).waitFor()
  assert.equal(await errorPage.getByRole('button', { name: /Generate Incident/i }).isEnabled(), true, 'Generation must be available after a provider failure')
  record('Provider error is visible', 'isolated Playwright with explicitly injected failure', { screenshot: await screenshot(errorPage, 'injected-error') })
  await errorPage.context().close()
  if (live) {
    if (!editOnly) {
    await start(desktop)
    await readyApproval(desktop, 'desktop-live')
    const initial = sse(fixtures.get('/api/agent-run').body)
    record('Initial SSE terminal state', capturedInputFile ? 'captured prior production SSE replayed through current UI' : 'in-page clone of real production response', { terminalDone: initial.some(item => item.event === 'done'), eventCount: initial.length, provenance: evidence.initialInputProvenance, transportErrors: evidence.errors.filter(item => item.url?.endsWith('/api/agent-run') || item.path === '/api/agent-run') })
    assert(initial.some(item => item.event === 'done'), 'Initial generation response did not include terminal done event')
    const incidentAudit = initial.find(item => item.event === 'api_call' && item.data.type === 'llm')?.data
    const auditRows = [validateModel(incidentAudit, 'incident generation')]
    for (const path of toolPaths) auditRows.push(validateModel(JSON.parse(fixtures.get(path).body).llmAudit, path))
    record(capturedInputFile ? 'Prior real incident and ten tool audits supplied to current UI' : 'Real incident and ten synthetic tool model calls', capturedInputFile ? 'captured successful production API inputs; no current generation/tool calls' : 'production API response/audit', { audits: auditRows, provenance: evidence.initialInputProvenance })
    assert(initial.some(item => item.event === 'agent_route' && item.data.kind === 'backtrack'), 'No actual cyclic routing event')
    await tabs(desktop, 'desktop-approval')
    await reveal(desktop, /evidence|api|audit/i)
    const filter = desktop.locator('.apiLog select')
    if (await filter.count()) {
      for (const value of ['llm', 'tool', 'human', 'routing', 'error', 'all']) {
        await filter.selectOption(value)
        evidence.controls.push({ label: 'desktop-live', type: 'API filter', name: value, result: 'selected' })
      }
      for (const row of await desktop.locator('details.apiRow').all()) {
        await row.locator('summary').click()
        assert(await row.getAttribute('open') !== null)
        await row.locator('summary').click()
      }
    }
    await reveal(desktop, /investigation|overview/i)
    await desktop.getByRole('button', { name: /^Approve$/i }).click()
    await reportAndExport(desktop, 'desktop-live')
    await reveal(desktop, /execution graph/i)
    await desktop.locator('.graphPanel').scrollIntoViewIfNeeded()
    await desktop.screenshot({ path: join(output, `${prefix}-completed-graph-viewport.png`), fullPage: false })
    await screenshot(desktop, 'completed-graph')
    await reveal(desktop, /report/i)
    const popupPromise = desktop.waitForEvent('popup')
    await desktop.locator('#final-report').getByRole('button', { name: /PDF/i }).click()
    const popup = await popupPromise
    popup.on('console', message => { if (message.type() === 'error') evidence.errors.push({ label: 'pdf-popup', type: 'console', text: message.text() }) })
    await popup.locator('h1').waitFor()
    await popup.evaluate(() => { window.__verificationPrintCalls = 0; window.print = () => { window.__verificationPrintCalls += 1 } })
    await popup.getByRole('button', { name: /Print or Save as PDF/i }).click()
    assert.equal(await popup.evaluate(() => window.__verificationPrintCalls), 1, 'Print button failed, possibly CSP inline handler blocked')
    const pdf = join(output, `${prefix}-incident-report.pdf`)
    await popup.pdf({ path: pdf, format: 'A4', printBackground: true })
    record('PDF export and print control', 'isolated Playwright popup; browser-generated PDF', { pdf, nativePrintDialog: 'Not manually tested; parent Chrome pass required' })
    await popup.close()
    await reveal(desktop, /evidence|checkpoint/i)
    const state = desktop.locator('[data-testid="checkpoint-row"] details summary').first()
    if (await state.count()) { await state.click(); await state.click() }
    await desktop.getByRole('button', { name: /^Fork$|Replay checkpoint/i }).first().click()
    await desktop.locator('[data-testid="checkpoint-row"][data-node="time_travel_fork"]').waitFor({ timeout: 180_000 })
    await Promise.allSettled(captureTasks)
    const replayResponse = evidence.requests.find(item => item.path === '/api/replay-run')
    const replayEvents = sse(replayResponse.body)
    assert(!replayEvents.some(item => item.event === 'error'))
    record('Snapshot alternate analysis', 'isolated Playwright + live production SSE; browser snapshot supplied to model, not native checkpoint resume', { audit: validateModel(replayEvents.find(item => item.event === 'api_call' && item.data.type === 'llm')?.data, 'replay'), screenshot: await screenshot(desktop, 'replay') })
    await desktop.context().close()
    } else await desktop.context().close()
    for (const decision of editOnly ? ['edit'] : ['reject', 'edit']) {
      const label = `${decision}-live-resume`
      const page = await makePage(label, decision === 'edit' ? { width: 390, height: 844 } : { width: 1440, height: 900 }, true)
      await start(page)
      await readyApproval(page, label)
      if (decision === 'edit') {
        await page.getByRole('button', { name: /^Edit$/ }).click()
        const args = JSON.parse(await page.locator('.approval textarea').inputValue())
        assert(args && typeof args === 'object' && !Array.isArray(args), 'Edit textarea must initially contain a JSON object, including when historical inputs encoded arguments as a JSON string')
        record('Historical string arguments normalized in Edit UI', 'isolated mobile Playwright against current frontend with historical production input', 'Textarea parses directly to a JSON object; verifier does not repair application input')
        const beforeInvalid = evidence.livePostCount
        await page.locator('.approval textarea').fill('{ invalid')
        await page.getByRole('button', { name: /Edit & Approve/ }).click()
        await page.getByText(/Invalid JSON/i).waitFor()
        assert.equal(evidence.livePostCount, beforeInvalid, 'Invalid JSON must not reach backend')
        record('Malformed containment edit blocked', 'isolated mobile Playwright', 'Validation error visible; no live request sent')
        args.durationMinutes = 15
        args.host = editedHost
        if ('target' in args) args.target = editedHost
        if ('hostname' in args) args.hostname = editedHost
        await page.locator('.approval textarea').fill(JSON.stringify(args, null, 2))
        await page.getByRole('button', { name: /^Review$/ }).click()
        await page.getByRole('button', { name: /^Edit$/ }).click()
        await page.getByRole('button', { name: /Edit & Approve/ }).click()
      } else await page.getByRole('button', { name: /^Reject$/ }).click()
      const exported = await reportAndExport(page, label)
      const human = exported.apiLogs.filter(log => log.type === 'human').at(-1)
      assert.equal(human.requestPayload.decision, decision)
      if (decision === 'edit') {
        assert.equal(human.requestPayload.editedArguments.durationMinutes, 15)
        assert.equal(human.requestPayload.editedArguments.host, editedHost)
      }
      const response = evidence.requests.filter(item => item.label === label && item.path === '/api/resume-run').at(-1)
      const resumedCheckpoint = sse(response.body).find(item => item.event === 'checkpoint' && item.data.node === 'containment_resume')?.data
      assert.equal(resumedCheckpoint?.state?.decision, decision, 'Backend checkpoint has wrong analyst decision')
      for (const log of resumedCheckpoint.state.containmentLogs) assert.equal(log.synthetic, true, 'Simulated containment result must be labeled synthetic')
      if (decision === 'reject') assert.equal(resumedCheckpoint.state.containmentLogs.length, 0, 'Rejected decision must not produce synthetic containment actions')
      else {
        assert(resumedCheckpoint.state.containmentLogs.length > 0)
        const firewall = resumedCheckpoint.state.containmentLogs.find(log => log.ruleName)
        const edr = resumedCheckpoint.state.containmentLogs.find(log => log.hostname)
        assert.equal(firewall?.target, editedHost, 'Edited target not used by simulated firewall action')
        assert.equal(firewall?.arguments?.durationMinutes, 15)
        assert.equal(edr?.hostname, editedHost, 'Edited host not used by simulated EDR action')
        assert.equal(edr?.durationMinutes, 15, 'Edited duration not used by simulated EDR action')
      }
      record(`${decision} decision reaches backend`, 'isolated Playwright + live production resume; captured original investigation reused', { decision, approvalSnapshotReused: true, serverCheckpoint: resumedCheckpoint })
      await tabs(page, label)
      const reportShortcut = page.getByRole('button', { name: /Read the report/i })
      if (await reportShortcut.count()) await reportShortcut.click()
      await layout(page, `${label}-complete`)
      await page.context().close()
    }
    const retryPage = await makePage('retry-fixture', { width: 390, height: 844 }, true, false, true)
    const postsBeforeRetryFixture = evidence.livePostCount
    await start(retryPage)
    const retry = retryPage.getByRole('button', { name: 'Retry missing evidence' })
    await retry.waitFor({ timeout: 30_000 })
    assert.equal(await retryPage.getByRole('button', { name: /^Approve$/ }).isDisabled(), true)
    await retry.click()
    await readyApproval(retryPage, 'retry-fixture')
    assert.equal(evidence.livePostCount, postsBeforeRetryFixture, 'Fixture retry must not incur live calls')
    const fixtureTools = evidence.requests.filter(item => item.label === 'retry-fixture' && toolPaths.includes(item.path))
    assert.equal(fixtureTools.filter(item => item.path === toolPaths[0]).length, 2, 'Missing tool should be retried once')
    for (const path of toolPaths.slice(1)) assert.equal(fixtureTools.filter(item => item.path === path).length, 1, 'Successful tools must not be retried')
    record('Retry missing evidence control', 'isolated mobile Playwright; one injected tool failure followed by captured successful production response', { livePaidRequests: 0, retriedTool: toolPaths[0], successfulToolsNotRepeated: 9, screenshot: await screenshot(retryPage, 'retry-recovered') })
    await retryPage.context().close()
  } else record('Paid investigation workflows', 'execution guard', 'Skipped until explicit --live authorization', 'NOT RUN')
  const audit = spawnSync('npm', ['audit', '--omit=dev', '--json'], { encoding: 'utf8', cwd: new URL('..', import.meta.url), timeout: 60_000 })
  await writeFile(join(output, `${prefix}-npm-audit.json`), audit.stdout || '{}')
  const auditJson = JSON.parse(audit.stdout || '{}')
  assert.equal(auditJson.metadata?.vulnerabilities?.total, 0, 'Production dependencies have reported vulnerabilities')
  record('Production dependency audit', 'npm audit --omit=dev', auditJson.metadata)
  assert.equal(evidence.errors.length, 0, `Console/network errors: ${JSON.stringify(evidence.errors)}`)
  record('Browser console and network', 'isolated Playwright listeners', 'No console errors, page errors, failed requests, or unexpected HTTP failures')
} catch (error) {
  record('Verification run', 'assertion', error.stack || String(error), 'FAIL')
  for (const [index, context] of browser.contexts().entries()) for (const page of context.pages()) await screenshot(page, `failure-context-${index}`).catch(() => undefined)
  process.exitCode = 1
} finally {
  await Promise.allSettled(captureTasks)
  evidence.finished = localTime()
  evidence.livePostsByEndpoint = Object.fromEntries(endpointCalls)
  await writeFile(join(output, `${prefix}-evidence.json`), JSON.stringify(evidence, null, 2))
  const rows = evidence.checks.map(item => `| ${item.requirement} | ${item.status} | ${item.method} | ${JSON.stringify(item.details).replaceAll('|', '\\|').replaceAll('\n', ' ').slice(0, 1000)} |`).join('\n')
  await writeFile(join(output, `${prefix}-evidence-matrix.md`), `# SOC verification evidence\n\nURL: ${baseUrl}\n\nCurrent deployment: ${evidence.deploymentId}; source: ${evidence.sourceCommit}.\n\nStarted: ${evidence.started}\n\nFinished: ${evidence.finished}\n\nMode: ${evidence.mode}. Real Chrome: ${evidence.manualChrome}.\n\nInitial scenario/tool input provenance: ${JSON.stringify(evidence.initialInputProvenance || 'Generated live on this deployment during this run')}.\n\nLive POSTs: ${evidence.livePostCount}/${evidence.paidRequestCap}. No top-ups. Dollar spend is not inferred from tokens; see provider billing if exact cost is needed.\n\n| Requirement | Result | Evidence source | Details |\n|---|---|---|---|\n${rows}\n\nFull response evidence, request provenance, and console/network results: ${prefix}-evidence.json.\n`)
  await browser.close()
  console.log(JSON.stringify({ output, mode: evidence.mode, livePostCount: evidence.livePostCount, failures: evidence.checks.filter(item => item.status === 'FAIL').length }))
}
