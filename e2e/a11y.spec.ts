/**
 * The WCAG A/AA gate for the HPKE Envelope lab.
 *
 * Four configurations — {dark, light} x {1280, 380} — each driven through every
 * state the lab can render, with a full scan after every single step. The
 * matrix is not padding: `html[data-theme='light']` re-declares every ink and
 * every surface, and 380px is where the break-it two-column grid and the chip
 * row collapse and the nonce table starts panning inside its `.tablewrap`.
 *
 * What the replaced spec did instead, and why none of it could be kept:
 *
 *  - `prepare()` injected `*{animation:none!important;transition:none!important}`,
 *    which does not exercise this sheet's `prefers-reduced-motion` block, it
 *    replaces it — and it also overrides `pipeline.ts`'s own
 *    `prefersReducedMotion()` branch, the lab's real reduced-motion path;
 *  - it force-set `.open` on every `<details>` from script rather than clicking
 *    the summaries, producing a document no visitor can load while never
 *    scanning the closed state every visitor lands on;
 *  - it ran a fixed five-click script and scanned ONCE at the end, so the empty
 *    nonce table, the un-run break-it panel, three of the four modes, the whole
 *    PSK branch, the other AEAD, the three key-regeneration buttons and every
 *    free-text input were built and discarded unmeasured;
 *  - it asserted `violations` only, so axe's `incomplete` bucket — where
 *    `aria-prohibited-attr` and every `color-mix` contrast result live — went
 *    unread;
 *  - and it had no oracle for reflow and none for keyboard-reachable scrollers.
 *
 * The `text control borders >= 3:1` tests are folded in here and deleted. They
 * queried `input, textarea, select` and nothing else — which is exactly the set
 * of elements `--ctl-border` was already applied to. See the commit message for
 * what that left unmeasured.
 */
import { test } from '@playwright/test';
import { NARROW, boot, driveAllStates, expectBaselineNotStale, reportCollected } from './gate';

test.beforeEach(async ({ page }) => {
  page.setDefaultTimeout(20_000);
});

// A collecting run (`A11Y_COLLECT=1`) records instead of throwing; this is what
// stops one being mistaken for a pass.
test.afterAll(() => {
  reportCollected();
});

for (const theme of ['dark', 'light'] as const) {
  test(`WCAG A/AA — ${theme}, 1280px`, async ({ page }) => {
    // ~45 scans per configuration, each an axe pass plus a full arithmetic
    // contrast walk. The budget is set to match the drive rather than the drive
    // being trimmed to fit the default.
    test.setTimeout(300_000);
    await page.setViewportSize({ width: 1280, height: 900 });
    await boot(page, theme);
    await driveAllStates(page, `${theme} 1280`);
    expectBaselineNotStale();
  });

  test(`WCAG A/AA — ${theme}, ${NARROW.width}px`, async ({ page }) => {
    test.setTimeout(300_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} ${NARROW.width}`);
    expectBaselineNotStale();
  });
}
