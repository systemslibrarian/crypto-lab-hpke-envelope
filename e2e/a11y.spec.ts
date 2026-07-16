import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Reveal collapsed content and drive the live demo so dynamic result regions
 * (seal status, break-it chips — including the alarm state — and the nonce
 * table) are present when axe scans.
 */
async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
  });
  // Seal twice so the nonce table has rows.
  await page.locator('#seal-btn').click();
  await page.locator('#seal-btn').click();
  // Matching delivery, then replay (alarm chip), then a mismatch (binding-held chip).
  await page.locator('#breakit-run').click();
  await expect(page.locator('#breakit-replay')).toBeEnabled();
  await page.locator('#breakit-replay').click();
  await page.getByRole('button', { name: /Flip one character/ }).click();
  await page.locator('#breakit-run').click();
  await expect(page.locator('#verdict-chip')).toContainText('BINDING HELD');
  await page.waitForTimeout(400);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});
