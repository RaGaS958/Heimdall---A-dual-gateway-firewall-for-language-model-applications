import { test, expect } from '@playwright/test'

const ROUTES = ['/', '/chat', '/simulation', '/analytics', '/immune', '/research', '/about', '/review', '/policies', '/debug']

test.describe('reduced motion', () => {
  test.use({ reducedMotion: 'reduce' })
  test('no smooth scroll, no autoplaying video, and the flow card is already drawn', async ({ page }) => {
    await page.goto('/')
    await page.waitForTimeout(900)
    expect(await page.evaluate(() => document.documentElement.classList.contains('lenis'))).toBe(false)
    expect(await page.locator('.hero-plate video').evaluate((v) => v.paused)).toBe(true)
    await expect(page.getByRole('button', { name: 'Play animation' })).toBeVisible()
    const hub = page.locator('.flow-hub')
    await hub.scrollIntoViewIfNeeded()
    expect(await hub.evaluate((el) => getComputedStyle(el).opacity)).toBe('1')
  })
})

test('nothing overflows sideways on a phone', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  for (const route of ROUTES) {
    await page.goto(route)
    await page.waitForTimeout(500)
    const over = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)
    expect(over, route).toBeLessThanOrEqual(1)
  }
})

test('the hero headline is readable before any animation finishes', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1, name: 'Stop hostile prompts at the gate.' })).toBeVisible()
})

test('the hero video has a poster, stays muted, and can be paused', async ({ page }) => {
  await page.goto('/')
  const video = page.locator('.hero-plate video')
  await expect(video).toHaveAttribute('poster', /heimdall-gate\.webp$/)
  expect(await video.evaluate((v) => v.muted)).toBe(true)
  await page.getByRole('button', { name: 'Pause animation' }).click()
  await expect(page.getByRole('button', { name: 'Play animation' })).toBeVisible()
  expect(await video.evaluate((v) => v.paused)).toBe(true)
})

test('the layer map lists every layer the middleware runs', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('.gate-card')).toHaveCount(9)
  await expect(page.locator('.gate-arbiter')).toHaveCount(2)
})

test('the pinned story swaps its step as the reader scrolls', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.goto('/')
  const story = page.locator('.sc')
  await expect(story).toBeAttached()
  const first = story.locator('.sc-content').first()
  const last = story.locator('.sc-content').last()
  const top = await story.evaluate((el) => el.getBoundingClientRect().top + scrollY)
  await page.evaluate((y) => scrollTo(0, y), top - 60)
  await expect(first).toBeVisible()
  const height = await story.evaluate((el) => el.offsetHeight)
  await page.evaluate((y) => scrollTo(0, y), top + height - 905)
  await expect(last).toBeVisible({ timeout: 6000 })
  await expect(first).toBeHidden()
})

test('one colour scheme: light page, navy ink, no dark surfaces behind text', async ({ page }) => {
  for (const route of ROUTES) {
    await page.goto(route)
    const [bg, ink] = await page.evaluate(() => [getComputedStyle(document.body).backgroundColor, getComputedStyle(document.body).color])
    expect(bg, route).toBe('rgb(255, 255, 255)')
    expect(ink, route).toBe('rgb(10, 15, 30)')
  }
})

test('every known limit is plain text with nothing in front of it', async ({ page }) => {
  await page.goto('/about')
  const rows = page.locator('#limits .limits li')
  await expect(rows).toHaveCount(5)
  for (let i = 0; i < 5; i++) {
    const row = rows.nth(i)
    await row.scrollIntoViewIfNeeded()
    await expect(row).toBeVisible()
    const state = await row.evaluate((el) => {
      const box = el.querySelector('p').getBoundingClientRect()
      const top = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2)
      return { opacity: getComputedStyle(el).opacity, uncovered: el.contains(top), position: getComputedStyle(el).position }
    })
    expect(state).toEqual({ opacity: '1', uncovered: true, position: 'static' })
  }
})
