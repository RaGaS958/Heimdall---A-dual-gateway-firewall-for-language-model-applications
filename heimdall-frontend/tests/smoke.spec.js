import { test, expect } from '@playwright/test'

const pages = [['/', 'Stop hostile prompts at the gate.'], ['/chat', 'Console'], ['/simulation', 'Attack Lab'], ['/analytics', 'Analytics'],
  ['/immune', 'Immune system'], ['/research', 'Research'], ['/about', 'About Heimdall'], ['/review', 'Review queue'], ['/policies', 'Policies'], ['/debug', 'Debug console']]

for (const [path, heading] of pages) {
  test(`${path} renders without console errors`, async ({ page }) => {
    const errors = []
    page.on('pageerror', (e) => errors.push(e.message))
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible()
    expect(errors).toEqual([])
  })
}

test('no default credential ships in the admin form', async ({ page }) => {
  await page.goto('/debug')
  await expect(page.getByLabel('Admin key')).toHaveValue('')
})

test('offline backend produces an explained error on the Attack Lab', async ({ page }) => {
  await page.route('**/api/**', (route) => route.abort())
  await page.goto('/simulation')
  await page.getByRole('button', { name: /Run \d+ cases/ }).click()
  await expect(page.getByText('Firewall not reachable')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible()
})

test('a proxy 500 with no body is explained as the firewall being unreachable', async ({ page }) => {
  await page.route('**/api/scan', (route) => route.fulfill({ status: 500, body: '' }))
  await page.goto('/simulation')
  await page.getByRole('button', { name: /Run \d+ cases/ }).click()
  await page.getByRole('row').nth(1).click()
  await expect(page.getByText('Firewall not reachable').first()).toBeVisible()
})
