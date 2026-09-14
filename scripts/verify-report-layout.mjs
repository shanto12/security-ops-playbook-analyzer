import assert from 'node:assert/strict'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { chromium } from 'playwright'

// All POSTs are fulfilled from captured production responses or aborted. No
// model endpoint can be reached. The deployed frontend and GET assets are real.
const baseUrl = process.env.VERIFY_URL || 'https://security-ops-playbook-analyzer.netlify.app'
const output = process.env.VERIFY_OUTPUT || '/Users/shanto/Documents/Playground/portfolio-curation-2026-09-14/soc'
const inputFile = process.env.VERIFY_INPUT_EVIDENCE || join(output, 'attempt-6-5952b0d/production-evidence.json')
const cssFile = process.env.VERIFY_CSS_FILE
const prefix = cssFile ? 'layout-css-preview' : 'layout-production'
const localTime = () => new Intl.DateTimeFormat('en-US', { timeZone: 'America/Chicago', dateStyle: 'full', timeStyle: 'long' }).format(new Date())
const prior = JSON.parse(await readFile(inputFile, 'utf8'))
const fixtures = new Map(prior.requests.filter(item => item.label === 'edit-live-resume' && item.method === 'POST' && item.status === 200 && item.complete).map(item => [item.path, item]))
assert.equal(fixtures.size, 12, 'Expected captured generation, ten tool responses, and successful edited resume')
const css = cssFile ? await readFile(cssFile, 'utf8') : undefined
const evidence = { url: baseUrl, deploymentId: process.env.VERIFY_DEPLOY_ID, sourceCommit: process.env.VERIFY_COMMIT, started: localTime(), mode: css ? 'Deployed frontend with explicitly injected local CSS; not production CSS proof' : 'Real deployed frontend with all POST responses explicitly replayed from captured evidence', inputFile, inputDeployment: prior.deploymentId, initialInputProvenance: prior.initialInputProvenance, cssOverride: cssFile ? { path: cssFile, sha256: createHash('sha256').update(css).digest('hex') } : undefined, livePosts: 0, fixturePosts: [], unexpectedPosts: [], errors: [], checks: [] }
await mkdir(output, { recursive: true })
const browser = await chromium.launch({ headless: true, ...(process.env.VERIFY_BROWSER_EXECUTABLE ? { executablePath: process.env.VERIFY_BROWSER_EXECUTABLE } : {}) })
evidence.browserVersion = browser.version()
const sizes = [{ name: 'mobile', width: 390, height: 844 }, { name: 'desktop', width: 1440, height: 900 }, { name: 'large', width: 3840, height: 2160 }].filter(size => !process.env.VERIFY_LAYOUT_SIZE || size.name === process.env.VERIFY_LAYOUT_SIZE)
async function framePanel(page, selector) {
  await page.locator(selector).evaluate(panel => window.scrollTo({ top: Math.max(0, window.scrollY + panel.getBoundingClientRect().top - 24), behavior: 'instant' }))
}
try {
  for (const viewport of sizes) {
    const context = await browser.newContext({ viewport, timezoneId: 'America/Chicago', reducedMotion: 'reduce' })
    const page = await context.newPage()
    page.on('console', message => { if (message.type() === 'error') evidence.errors.push({ viewport: viewport.name, type: 'console', text: message.text() }) })
    page.on('pageerror', error => evidence.errors.push({ viewport: viewport.name, type: 'pageerror', text: error.message }))
    page.on('requestfailed', request => evidence.errors.push({ viewport: viewport.name, type: 'requestfailed', url: request.url(), text: request.failure()?.errorText }))
    page.on('response', response => { if (response.status() >= 400) evidence.errors.push({ viewport: viewport.name, type: 'http', url: response.url(), status: response.status() }) })
    await page.route('**/*', async route => {
      const request = route.request()
      if (request.method() !== 'POST') return route.continue()
      const path = new URL(request.url()).pathname
      const fixture = fixtures.get(path)
      if (new URL(request.url()).origin !== new URL(baseUrl).origin || !fixture) {
        evidence.unexpectedPosts.push({ viewport: viewport.name, path, url: request.url() })
        return route.abort('blockedbyclient')
      }
      if (path === '/api/resume-run') {
        const submitted = request.postDataJSON()
        assert.equal(submitted.decision, 'edit')
        assert.deepEqual(submitted.editedArguments, { host_id: 'SOC-VERIFY-EDITED-HOST', duration_minutes: 15, disable_user: false })
      }
      evidence.fixturePosts.push({ viewport: viewport.name, path, inputDeployment: prior.deploymentId, originalSource: fixture.source, sha256: createHash('sha256').update(fixture.body).digest('hex') })
      return route.fulfill({ status: fixture.status, contentType: fixture.contentType || (path.endsWith('-run') ? 'text/event-stream' : 'application/json'), body: fixture.body })
    })
    await page.goto(baseUrl, { waitUntil: 'networkidle' })
    if (css) await page.addStyleTag({ content: css })
    if (viewport.name === 'mobile') await page.screenshot({ path: join(output, 'production-mobile-initial.png'), fullPage: false, animations: 'disabled' })
    await page.getByRole('button', { name: /Generate Incident/i }).click()
    await page.waitForFunction(() => [...document.querySelectorAll('button')].some(button => button.textContent.trim() === 'Approve' && !button.disabled), null, { timeout: 30_000 })
    await page.getByRole('button', { name: /^Edit$/ }).click()
    const args = JSON.parse(await page.getByRole('textbox', { name: 'Containment arguments JSON' }).inputValue())
    assert(args && typeof args === 'object' && !Array.isArray(args), 'Application must normalize historical argument strings')
    await page.getByRole('textbox', { name: 'Containment arguments JSON' }).fill(JSON.stringify({ host_id: 'SOC-VERIFY-EDITED-HOST', duration_minutes: 15, disable_user: false }, null, 2))
    await page.getByRole('button', { name: 'Edit & Approve' }).click()
    await page.getByRole('tab', { name: /^Report/ }).click()
    await page.locator('#final-report').getByText('Executive Summary', { exact: true }).waitFor()
    await page.evaluate(() => document.fonts.ready)
    const geometry = await page.locator('#final-report').evaluate(panel => {
      const panelRect = panel.getBoundingClientRect()
      const box = element => {
        const rect = element.getBoundingClientRect()
        const style = getComputedStyle(element)
        return { tag: element.tagName.toLowerCase(), className: element.className, text: element.textContent.trim().slice(0, 220), left: rect.left, right: rect.right, width: rect.width, clientWidth: element.clientWidth, scrollWidth: element.scrollWidth, overflowX: style.overflowX, minWidth: style.minWidth, gridTemplateColumns: style.gridTemplateColumns, overflowWrap: style.overflowWrap }
      }
      const elements = [panel, ...panel.querySelectorAll('.reportBody, .reportBody p, .reportBody ul, .reportBody li, .reportBody h3')]
      const measured = elements.map(box)
      const violations = []
      for (const [index, element] of elements.entries()) {
        const data = measured[index]
        if (data.scrollWidth > data.clientWidth + 2) violations.push({ kind: 'inner-scroll-overflow', ...data })
        if (element !== panel && (data.left < panelRect.left - 2 || data.right > panelRect.right + 2)) violations.push({ kind: 'element-outside-report-panel', ...data })
        if (['P', 'LI', 'H3'].includes(element.tagName)) {
          const range = document.createRange()
          range.selectNodeContents(element)
          for (const textRect of range.getClientRects()) if (textRect.left < panelRect.left - 2 || textRect.right > panelRect.right + 2) violations.push({ kind: 'text-outside-clipping-panel', text: data.text, left: textRect.left, right: textRect.right, panelLeft: panelRect.left, panelRight: panelRect.right })
        }
      }
      return { viewport: innerWidth, documentWidth: document.documentElement.scrollWidth, panel: box(panel), elements: measured, violations }
    })
    const fullPath = join(output, `${prefix}-${viewport.name}-report-full.png`)
    const viewportPath = join(output, `${prefix}-${viewport.name}-report-viewport.png`)
    await page.screenshot({ path: fullPath, fullPage: true, animations: 'disabled' })
    await framePanel(page, '#final-report')
    await page.screenshot({ path: viewportPath, fullPage: false, animations: 'disabled' })
    evidence.checks.push({ viewport, geometry, fullPath, viewportPath, status: geometry.violations.length || geometry.documentWidth > viewport.width + 2 ? 'FAIL' : 'PASS' })
    assert.equal(geometry.documentWidth <= viewport.width + 2, true, `${viewport.name}: document overflow`)
    assert.equal(geometry.violations.length, 0, `${viewport.name}: report inner clipping: ${JSON.stringify(geometry.violations)}`)
    if (viewport.name === 'desktop') {
      await page.getByRole('tab', { name: 'Execution graph' }).click()
      await framePanel(page, '.graphPanel')
      await page.screenshot({ path: join(output, 'production-completed-graph-viewport.png'), fullPage: false, animations: 'disabled' })
      await page.getByRole('tab', { name: /^Report/ }).click()
      await framePanel(page, '#final-report')
      await page.screenshot({ path: join(output, 'production-desktop-live-report-viewport.png'), fullPage: false, animations: 'disabled' })
    }
    console.log(`PASS: ${viewport.name} ${viewport.width}×${viewport.height}; ${geometry.elements.length} report elements fit; zero model calls`)
    await context.close()
  }
  assert.equal(evidence.unexpectedPosts.length, 0, 'An unexpected POST was blocked')
  assert.equal(evidence.errors.length, 0, 'Browser/network errors detected')
} catch (error) {
  evidence.failure = error.stack || String(error)
  process.exitCode = 1
  console.log(`FAIL: ${String(error)}`)
} finally {
  await browser.close()
  evidence.browserClosed = true
  evidence.finished = localTime()
  await writeFile(join(output, `${prefix}-evidence.json`), JSON.stringify(evidence, null, 2))
  await writeFile(join(output, `${prefix}-evidence.md`), `# Report layout verification\n\nMode: ${evidence.mode}.\n\nDeployment: ${evidence.deploymentId}; source: ${evidence.sourceCommit}.\n\nWindow: ${evidence.started} to ${evidence.finished}.\n\nAll ${evidence.fixturePosts.length} POSTs were explicit captured-response fixtures; live POSTs: 0. Captured report source: deployment ${prior.deploymentId}. Initial input provenance is retained in the JSON evidence. No model call was made.\n\n| Viewport | Result | Report elements measured | Clipping violations |\n|---|---|---:|---:|\n${evidence.checks.map(check => `| ${check.viewport.width}×${check.viewport.height} | ${check.status} | ${check.geometry.elements.length} | ${check.geometry.violations.length} |`).join('\n')}\n\nConsole/network errors: ${evidence.errors.length}. Unexpected POSTs blocked: ${evidence.unexpectedPosts.length}. Browser closed: ${evidence.browserClosed}.\n\n${evidence.failure || 'All report elements and text ranges fit within the report panel.'}\n`)
  console.log(JSON.stringify({ output, prefix, results: evidence.checks.map(check => ({ viewport: check.viewport.name, status: check.status })), livePosts: evidence.livePosts, browserClosed: true }))
}
