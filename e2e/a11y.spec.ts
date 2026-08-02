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

/**
 * WCAG 1.4.11 regression: text-entry control boundaries (input/textarea/select
 * borders) must hit >= 3:1 against at least one adjacent surface, after
 * compositing translucent colors over the real ancestor backgrounds.
 */
async function measureControlBorders(
  page: Page,
): Promise<Array<{ sel: string; best: number }>> {
  return page.evaluate(() => {
    const parse = (c: string): number[] => {
      const m = c.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?\s*\)/);
      return m ? [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]] : [0, 0, 0, 0];
    };
    const comp = (fg: number[], bg: number[]): number[] =>
      [0, 1, 2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat([1]);
    const lum = ([r, g, b]: number[]): number => {
      const f = (v: number) => {
        v /= 255;
        return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const ratio = (a: number[], b: number[]): number => {
      const l1 = lum(a);
      const l2 = lum(b);
      return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
    };
    const effBg = (start: Element | null): number[] => {
      const stack: number[][] = [];
      let node: Element | null = start;
      while (node) {
        const c = parse(getComputedStyle(node).backgroundColor);
        if (c[3] > 0) stack.push(c);
        if (c[3] >= 1) break;
        node = node.parentElement;
      }
      let bg = [255, 255, 255, 1];
      for (let i = stack.length - 1; i >= 0; i--) bg = comp(stack[i], bg);
      return bg;
    };
    const TEXTY = ['', 'text', 'number', 'password', 'email', 'search', 'url', 'tel'];
    const out: Array<{ sel: string; best: number }> = [];
    document.querySelectorAll('input, textarea, select').forEach((el) => {
      if (el.tagName === 'INPUT' && !TEXTY.includes((el.getAttribute('type') || '').toLowerCase())) return;
      const cs = getComputedStyle(el);
      const rect = el.getBoundingClientRect();
      if (cs.display === 'none' || cs.visibility === 'hidden' || rect.width === 0 || rect.height === 0) return;
      if ((parseFloat(cs.borderTopWidth) || 0) === 0) return;
      const outer = effBg(el.parentElement);
      const ownBg = parse(cs.backgroundColor);
      const inner = ownBg[3] >= 1 ? ownBg : comp(ownBg, outer);
      const borderRaw = parse(cs.borderTopColor);
      const best = Math.max(ratio(comp(borderRaw, outer), outer), ratio(comp(borderRaw, inner), inner));
      out.push({
        sel: el.tagName.toLowerCase() + (el.id ? '#' + el.id : ''),
        best: Math.round(best * 100) / 100,
      });
    });
    return out;
  });
}

for (const theme of ['dark', 'light'] as const) {
  test(`text control borders >= 3:1 — ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    if (theme === 'light') {
      await page.locator('#cl-theme-toggle').click();
      await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    }
    const rows = await measureControlBorders(page);
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.filter((r) => r.best < 3)).toEqual([]);
  });
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
