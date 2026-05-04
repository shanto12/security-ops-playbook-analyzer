import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

describe('App', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: RequestInfo | URL) => {
        if (String(url).includes('/api/health')) {
          return Response.json({
            service: 'soc-ai-agent-demo',
            status: 'ok',
            mode: 'live-glm',
            provider: 'z.ai',
            model: 'glm-5.1',
            endpoint: 'https://api.z.ai/api/coding/paas/v4',
            checkedAt: new Date().toISOString(),
            capabilities: { incident_generation: true },
            models: ['glm-5.1', 'glm-5-turbo', 'glm-4.7'],
          })
        }
        return Response.json({})
      }),
    )
  })

  it('renders the LangGraph SOC workflow shell', async () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: /soc ai agent demo/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /generate incident/i })).toBeInTheDocument()
    expect(await screen.findByText(/LIVE GLM/i)).toBeInTheDocument()
    expect(screen.getByText(/Live LangGraph Execution/i)).toBeInTheDocument()
    expect(screen.getByText(/Cyclic Handoff Trace/i)).toBeInTheDocument()
    expect(screen.getByText(/Checkpoints & Time Travel/i)).toBeInTheDocument()
  })
})
