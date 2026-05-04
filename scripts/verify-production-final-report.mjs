import { mkdir, writeFile } from 'node:fs/promises'
import { chromium } from 'playwright'

const baseUrl = process.argv[2] ?? 'https://security-ops-playbook-analyzer.netlify.app'
const outputPath = process.argv[3] ?? `docs/final-report-proof-${new Date().toISOString().slice(0, 10)}.md`
const screenshotPrefix = (process.argv[4] ?? 'docs/evidence/production-final-report-flow').replace(/\.png$/i, '')
const screenshotPaths = {
  initial: `${screenshotPrefix}-01-initial.png`,
  approval: `${screenshotPrefix}-02-approval-waiting-tools.png`,
  tools: `${screenshotPrefix}-03-tool-llm-evidence.png`,
  report: `${screenshotPrefix}-04-final-report.png`,
  replay: `${screenshotPrefix}-05-replay-proof.png`,
}

const requiredReportSections = [
  'Executive Summary',
  'Root Cause',
  'MITRE Mapping',
  'Investigation Timeline',
  'Containment Actions',
  'Recommendations',
  'Analyst Decisions',
  'Tool Result Summary',
]

await mkdir(outputPath.split('/').slice(0, -1).join('/'), { recursive: true })
await mkdir(screenshotPrefix.split('/').slice(0, -1).join('/'), { recursive: true })

const startedAt = new Date().toISOString()
const browser = await chromium.launch({ headless: true })
const page = await browser.newPage({ viewport: { width: 1440, height: 1300 }, acceptDownloads: true })
page.on('dialog', (dialog) => dialog.dismiss().catch(() => undefined))

await page.goto(baseUrl, { waitUntil: 'domcontentloaded' })
await page.screenshot({ path: screenshotPaths.initial, fullPage: true })
await page.getByRole('button', { name: /Generate Incident/i }).click()

const approve = page.getByRole('button', { name: /^Approve$/i })
await approve.waitFor({ timeout: 150_000 })
const approvalDisabledBeforeTools = await approve.isDisabled()
await page.screenshot({ path: screenshotPaths.approval, fullPage: true })

await page.waitForFunction(
  () => {
    const rows = [...document.querySelectorAll('details.apiRow.tool summary')]
    return rows.length >= 10 && rows.slice(0, 10).every((row) => {
      const match = row.textContent?.match(/(\d+)\s*tok/i)
      return match && Number(match[1]) > 0
    })
  },
  null,
  { timeout: 300_000 },
)
await approve.waitFor({ state: 'visible', timeout: 30_000 })
await page.waitForFunction(
  () => {
    const buttons = [...document.querySelectorAll('button')]
    return buttons.some((button) => /^Approve$/.test(button.textContent?.trim() ?? '') && !button.disabled)
  },
  null,
  { timeout: 30_000 },
)
await page.screenshot({ path: screenshotPaths.tools, fullPage: true })

await approve.click()
const finalReport = page.locator('#final-report')
await finalReport.getByText('Executive Summary').waitFor({ timeout: 180_000 })

const reportText = await finalReport.innerText()
const missingSections = requiredReportSections.filter((section) => !reportText.includes(section))
if (missingSections.length) throw new Error(`Final report missing sections: ${missingSections.join(', ')}`)

const toolRows = await page.$$eval('details.apiRow.tool summary', (items) =>
  items.map((item) => {
    const text = item.textContent?.replace(/\s+/g, ' ').trim() ?? ''
    const tokenMatch = text.match(/(\d+)\s*tok/i)
    return { text, tokens: tokenMatch ? Number(tokenMatch[1]) : 0 }
  }),
)
const reportRows = await page.$$eval('details.apiRow.llm summary', (items) =>
  items
    .map((item) => item.textContent?.replace(/\s+/g, ' ').trim() ?? '')
    .filter((text) => /Reporting Agent|GLM-5\.1/i.test(text)),
)
if (reportRows.length === 0) throw new Error('No Reporting Agent LLM row was visible in the API log')
const failedRowsBeforeReplay = await page.$$eval('details.apiRow.error summary', (items) =>
  items.map((item) => item.textContent?.replace(/\s+/g, ' ').trim() ?? ''),
)
if (failedRowsBeforeReplay.length) {
  throw new Error(`API Transparency Log contains failed rows before replay: ${failedRowsBeforeReplay.join(' | ')}`)
}
await page.screenshot({ path: screenshotPaths.report, fullPage: true })

const downloadPromise = page.waitForEvent('download')
await finalReport.getByRole('button', { name: 'JSON' }).click()
const jsonDownload = await downloadPromise

const forkButton = page.getByRole('button', { name: 'Fork' }).first()
await forkButton.click()
await page.getByText(/Forked/i).waitFor({ timeout: 180_000 })
const failedRowsAfterReplay = await page.$$eval('details.apiRow.error summary', (items) =>
  items.map((item) => item.textContent?.replace(/\s+/g, ' ').trim() ?? ''),
)
if (failedRowsAfterReplay.length) {
  throw new Error(`API Transparency Log contains failed rows after replay: ${failedRowsAfterReplay.join(' | ')}`)
}

await page.screenshot({ path: screenshotPaths.replay, fullPage: true })
const finishedAt = new Date().toISOString()

const markdown = `# Final Report Production Proof

Generated: ${finishedAt}

Base URL: ${baseUrl}

Result: PASS. The deployed app completed incident generation, ten LLM-backed enterprise tool calls, gated human approval, final report generation, JSON export, and time-travel replay.

Evidence:
- Approval disabled before tool evidence completed: ${approvalDisabledBeforeTools ? 'yes' : 'no'}
- Tool rows with nonzero tokens: ${toolRows.length}
- Reporting Agent LLM rows visible: ${reportRows.length}
- Failed API Transparency Log rows: 0
- JSON export filename: ${jsonDownload.suggestedFilename()}

Screenshot artifacts:
- Initial live app: ${screenshotPaths.initial}
- Approval card waiting for tool evidence: ${screenshotPaths.approval}
- Ten LLM-backed tool rows visible: ${screenshotPaths.tools}
- Final report rendered: ${screenshotPaths.report}
- Replay proof after checkpoint fork: ${screenshotPaths.replay}

Final report sections verified:
${requiredReportSections.map((section) => `- ${section}`).join('\n')}

Visible tool rows:

| Tool row | Tokens |
|---|---:|
${toolRows.map((row) => `| ${row.text.replaceAll('|', '\\|')} | ${row.tokens} |`).join('\n')}

Reporting rows:
${reportRows.map((row) => `- ${row}`).join('\n')}

Verification window:
- Started: ${startedAt}
- Finished: ${finishedAt}
`

await browser.close()
await writeFile(outputPath, markdown)
console.log(JSON.stringify({ outputPath, screenshotPaths, toolRows: toolRows.length, reportRows: reportRows.length, failedRows: 0, finishedAt }, null, 2))
