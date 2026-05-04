import { expect, test } from '@playwright/test'

test('renders first viewport on desktop and mobile', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: /SOC AI Agent Demo/i })).toBeVisible()
  await expect(page.getByRole('button', { name: /Generate Incident/i })).toBeVisible()
  await expect(page.getByText(/Live LangGraph Execution/i)).toBeVisible()
})
