import type { FinalReport, Incident, RunState } from './types'

export function downloadJson(filename: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

export function downloadReportPdf(incident: Incident | undefined, report: FinalReport | undefined) {
  if (!incident || !report) return

  const reportWindow = window.open('', '_blank', 'noopener,noreferrer')
  if (!reportWindow) return

  const list = (items: unknown) => safeList(items).map((item) => `<li>${escapeHtml(item)}</li>`).join('')
  const section = (title: string, body: unknown) => `
    <section>
      <h2>${escapeHtml(title)}</h2>
      ${Array.isArray(body) ? `<ul>${list(body)}</ul>` : `<p>${escapeHtml(String(body ?? ''))}</p>`}
    </section>
  `

  reportWindow.document.write(`
    <!doctype html>
    <html>
      <head>
        <title>${escapeHtml(incident.incidentId)} SOC report</title>
        <style>
          :root { color: #142022; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
          body { margin: 36px; line-height: 1.5; }
          header { border-bottom: 2px solid #142022; margin-bottom: 24px; padding-bottom: 16px; }
          h1 { font-size: 24px; margin: 0 0 8px; }
          h2 { font-size: 14px; margin: 22px 0 8px; text-transform: uppercase; letter-spacing: .08em; }
          p, li { font-size: 12px; }
          ul { padding-left: 18px; }
          .meta { display: grid; gap: 6px; grid-template-columns: repeat(2, minmax(0, 1fr)); font-size: 11px; }
          .meta span { border: 1px solid #cad4d8; padding: 8px; }
          @page { margin: 0.6in; }
          @media print { body { margin: 0; } button { display: none; } }
        </style>
      </head>
      <body>
        <button onclick="window.print()">Print or Save as PDF</button>
        <header>
          <h1>SOC AI Agent Incident Report</h1>
          <div class="meta">
            <span><strong>Incident:</strong> ${escapeHtml(incident.incidentId)}</span>
            <span><strong>Severity:</strong> ${escapeHtml(incident.severity)}</span>
            <span><strong>Type:</strong> ${escapeHtml(incident.incidentType)}</span>
            <span><strong>Timestamp:</strong> ${escapeHtml(incident.timestamp)}</span>
            <span><strong>User:</strong> ${escapeHtml(incident.affectedUser)}</span>
            <span><strong>Host:</strong> ${escapeHtml(incident.affectedHost)}</span>
          </div>
        </header>
        ${section('Executive Summary', report.executiveSummary)}
        ${section('Root Cause', report.rootCause)}
        ${section('MITRE ATT&CK Mapping', report.mitreMapping)}
        ${section('Investigation Timeline', report.timeline)}
        ${section('Containment Actions', report.containmentActions)}
        ${section('Recommendations', report.recommendations)}
        ${section('Analyst Decisions', report.analystDecisions)}
        ${section('Tool Result Summary', report.toolResultSummary)}
        <script>window.addEventListener('load', () => window.print())</script>
      </body>
    </html>
  `)
  reportWindow.document.close()
}

export function buildRunExport(state: RunState) {
  return {
    exportedAt: new Date().toISOString(),
    runId: state.runId,
    threadId: state.threadId,
    incident: state.incident,
    checkpoints: state.checkpoints,
    timeline: state.timeline,
    apiLogs: state.apiLogs,
    apiTransparencyLog: state.apiLogs,
    approval: state.approval,
    report: state.report,
  }
}

function escapeHtml(value: string) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => {
    switch (character) {
      case '&':
        return '&amp;'
      case '<':
        return '&lt;'
      case '>':
        return '&gt;'
      case '"':
        return '&quot;'
      default:
        return '&#39;'
    }
  })
}

function safeList(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item))
  if (typeof value === 'string' && value.trim()) return [value]
  return []
}
