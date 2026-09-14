import process from 'node:process'
import '@testing-library/jest-dom/vitest'

import { beforeEach, vi } from 'vitest'
beforeEach(() => { vi.stubGlobal('Netlify', { env: { get: (name: string) => process.env[name] } }) })
