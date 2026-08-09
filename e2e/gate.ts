import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The spec this file
 *     replaces opened its `prepare()` with
 *     `addStyleTag('*{animation:none!important;transition:none!important}')`
 *     and then force-set `.open` on every `<details>`.
 *
 *     The style tag does not exercise this sheet's own
 *     `@media (prefers-reduced-motion: reduce)` block, it replaces it — and it
 *     also overrides `pipeline.ts`'s `prefersReducedMotion()` branch, which is
 *     the lab's real reduced-motion path: with the preference set it drops the
 *     260ms per-stage step to 0 and the `stage-active` cleanup timeout with it.
 *     A suite that paints over both cannot see either. This gate emulates the
 *     preference for real, asserts it took effect, and lets the lab respond.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. Every panel is built in TypeScript and appended to
 *     `#app` — `main.ts` throws if the mount is missing, but axe over a
 *     half-built page passes having checked nothing.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Soft-gate collection mode — strict unless `A11Y_COLLECT` is set.
 *
 * Fixing a page one thrown assertion at a time means one full four-config run
 * per defect. `A11Y_COLLECT=1 npx playwright test` instead records every failed
 * assertion, finishes the drive, and dumps the lot, so a page can be fixed in
 * one pass.
 *
 * The safety property that makes this permanent rather than a temporary hack:
 * `reportCollected()` runs after the suite and THROWS if a collecting run
 * recorded anything. A collection run therefore cannot be mistaken for a
 * passing gate — it fails, loudly, with the whole list attached — and with the
 * env var unset not one line of this behaves differently from a plain `expect`.
 */
const COLLECTING = Boolean(process.env.A11Y_COLLECT);
const collected: string[] = [];

async function soft(label: string, assertion: () => void | Promise<void>): Promise<void> {
  if (!COLLECTING) {
    await assertion();
    return;
  }
  try {
    await assertion();
  } catch (err) {
    collected.push(`[${label}] ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** Fail the run if a collecting pass recorded anything. Call from `afterAll`. */
export function reportCollected(): void {
  if (!collected.length) return;
  const dump = collected.join('\n\n');
  const count = collected.length;
  collected.length = 0;
  throw new Error(
    `A11Y_COLLECT run recorded ${count} soft failure(s). This is NOT a pass.\n\n${dump}`
  );
}

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion handling
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  await soft(label, () =>
    expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([])
  );
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * THE DEFAULTS ARE ASSERTED, NOT ASSUMED. `LabStore` ships in mode Base with
 * AES-128-GCM, a fixed info/AAD/message, an empty transcript, and — critically
 * — `pskCtl.hidden = true`, because Base does not use a PSK. Which half of this
 * lab a scan sees depends on all of that: the PSK controls, the psk_id_hash
 * bytes and the Auth-mode second DH row simply do not exist at first paint, and
 * a gate that never leaves mode Base never measures any of them.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  // index.html's anti-flash script stamps `data-theme` unconditionally, reading
  // the same `theme` key the shared bar's toggle writes.
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // Every panel is constructed in TypeScript and appended to #app.
  for (const id of ['pipeline-h', 'modes-h', 'nonce-h', 'breakit-h', 'nongoals-h']) {
    await expect(page.locator(`#${id}`)).toBeVisible();
  }
  await expect(page.locator('#stage-kem')).toBeVisible();
  await expect(page.locator('#seal-btn')).toBeEnabled();

  // Shipped defaults, asserted.
  await expect(page.locator('#mode-0')).toBeChecked();
  await expect(page.locator('#aead-select')).toHaveValue('1');
  await expect(page.locator('#info-input')).toHaveValue('ode to a grecian urn');
  // Base mode uses no PSK, so its controls must start hidden. This one has bitten
  // before: `.psk-controls { display: flex }` outranks the UA's
  // `[hidden] { display: none }`, and the sheet carries an explicit
  // `[hidden]` rule to restore the attribute's meaning. Assert it works.
  await expect(page.locator('#psk-controls')).toBeHidden();
  // No message sealed yet: the nonce table holds only its base_nonce row.
  await expect(page.locator('.nonce-table tbody tr')).toHaveCount(1);
  await expect(page.locator('#breakit-replay')).toBeDisabled();
  await expect(page.locator('#verdict-chip')).toContainText('no delivery yet');
  // Every disclosure starts closed — force-opening them was the old spec's bug.
  expect(await page.locator('details[open]').count(), 'no disclosure may start open').toBe(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 32- and 65-byte hex blobs, a four-column nonce
 * table, and a two-column break-it grid.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. This sheet does not set
    // that rule today; the check is kept because adding it is the single most
    // tempting "fix" for a reflow failure and it would silence this oracle
    // permanently rather than fixing anything.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. The
    // nonce table has a huge bounding rect but is clipped by its `.tablewrap`
    // scroller and contributes nothing to the document's scroll width — naming
    // it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. That is the failure this whole check exists to
      // avoid: a viewport-level clip is the DEFECT, not a legitimate scroller.
      // Only a genuine scrolling container INSIDE the page excuses an overflow.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Anything inside a real scroller is reachable and is not a finding; only
    // what escapes the viewport with no way back is.
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  await soft(label, () =>
    expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull()
  );
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * `.tablewrap` already carries `tabindex="0"` and a `role`/`aria-label` pair.
 * It only actually overflows once several messages have been sealed and at
 * narrow widths, so this runs after every step at both viewports rather than
 * once at 1280 — the nonce table grows a row per Seal.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  await soft(label, () =>
    expect(
      Array.from(new Set(unreachable)),
      `scrolling regions with no keyboard route in state: ${label}`
    ).toEqual([])
  );
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *
 * Two whole classes of failure have no oracle here and were measured by hand
 * from screenshot pixels instead: WCAG 1.4.11 non-text contrast (control
 * boundaries, the changed-byte marker, the stage-active ring) and generated
 * content (`::before`/`::after`), which is neither an element nor a text node
 * and so is invisible to axe and to the arithmetic walk alike.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  await soft(label, () => expect(violations, `axe violations in state: ${label}`).toEqual([]));

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  await soft(label, () =>
    expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([])
  );

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  await soft(label, () =>
    expect(contrast, `measured contrast failures in state: ${label}`).toEqual([])
  );

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/** Open a `<details>` by clicking its summary — never by setting `.open`. */
async function openDisclosure(page: Page, summary: string): Promise<void> {
  const s = page.locator(summary).first();
  await s.click();
  await expect(s.locator('xpath=..')).toHaveAttribute('open', '');
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * The old spec drove a fixed five-click script once and scanned at the end, so
 * every state it built on the way — the un-run break-it panel, the empty nonce
 * table, three of the four modes, the whole PSK branch, the other AEAD — was
 * constructed and discarded unmeasured. Everything below is scanned where it
 * happens.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const at = async (label: string): Promise<void> => scan(page, `${theme} / ${label}`);

  await at('first paint (mode Base, nothing sealed)');

  // ── The four stage disclosures, opened by click ─────────────────────────
  await openDisclosure(page, '.panel-intro .expert > summary');
  await at('cryptographer disclosure open');
  for (const stage of ['stage-kem', 'stage-kdf', 'stage-aead']) {
    await openDisclosure(page, `#${stage} .stage-details > summary`);
    await expect(page.locator(`#${stage} .stage-internals .hexblock`).first()).toBeVisible();
    await at(`${stage} internals expanded`);
  }

  // ── Sealing: the empty transcript, then rows, then the stage-active ring ─
  // `prefersReducedMotion()` is true here, so the pipeline drops its 260ms
  // per-stage step — which is the reduced-motion branch the old spec's injected
  // `animation: none` made unreachable.
  await page.click('#seal-btn');
  await expect(page.locator('#seal-status')).toContainText('Sealed message #0');
  await expect(page.locator('.nonce-table tbody tr')).toHaveCount(2);
  await at('one message sealed');
  await page.click('#seal-btn');
  await page.click('#seal-btn');
  await expect(page.locator('.nonce-table tbody tr')).toHaveCount(4);
  await at('three messages sealed — nonce table populated');

  // ── Every mode. PSK modes reveal `#psk-controls` and change the byte diff;
  //    Auth modes add the sender pkS row and a second DH segment. ───────────
  for (const [value, name] of [
    ['1', 'PSK'],
    ['2', 'Auth'],
    ['3', 'AuthPSK'],
    ['0', 'Base'],
  ] as const) {
    await page.check(`#mode-${value}`);
    const pskVisible = value === '1' || value === '3';
    const psk = page.locator('#psk-controls');
    if (pskVisible) await expect(psk).toBeVisible();
    else await expect(psk).toBeHidden();
    await expect(page.locator('.byteview-title')).toContainText(name);
    // Changing the mode re-keys the context, so the transcript resets to the
    // base_nonce row alone — an empty state that comes back four times.
    await expect(page.locator('.nonce-table tbody tr')).toHaveCount(1);
    await at(`mode ${name}`);
    // Seal once in this mode so the AEAD stage has a real ct to show.
    await page.click('#seal-btn');
    await expect(page.locator('.nonce-table tbody tr')).toHaveCount(2);
    await at(`mode ${name}, one message sealed`);
  }

  // A PSK mode again, this time driving its own controls.
  await page.check('#mode-3');
  await expect(page.locator('#psk-controls')).toBeVisible();
  await page.click('#psk-controls .btn');
  await at('AuthPSK with a regenerated PSK');
  await page.fill('#pskid-input', 'lab psk rotated');
  await page.locator('#pskid-input').blur();
  await at('AuthPSK with an edited psk_id');

  // ── The other AEAD ──────────────────────────────────────────────────────
  await page.selectOption('#aead-select', '3');
  await expect(page.locator('#stage-aead .stage-sub')).toContainText('ChaCha20');
  await at('ChaCha20-Poly1305');
  await page.selectOption('#aead-select', '1');
  await at('back to AES-128-GCM');

  // ── The key-regeneration buttons ────────────────────────────────────────
  await page.check('#mode-2');
  const keyBtns = page.locator('.key-controls .btn');
  const keyBtnCount = await keyBtns.count();
  expect(keyBtnCount, 'the pipeline must offer key controls').toBe(3);
  for (let i = 0; i < keyBtnCount; i++) {
    await keyBtns.nth(i).click();
    await at(`key control ${i + 1} of ${keyBtnCount} pressed`);
  }
  await page.check('#mode-0');

  // ── Free-text inputs, including the empty-string edge ───────────────────
  await page.fill('#info-input', '');
  await page.locator('#info-input').blur();
  await at('info emptied');
  await page.fill('#msg-input', 'café ☕ — non-ASCII, so the byte count is not the character count');
  await page.locator('#msg-input').blur();
  await page.click('#seal-btn');
  await expect(page.locator('#seal-status')).toContainText('Sealed message #0');
  await at('non-ASCII message sealed');
  await page.fill('#aad-input', '');
  await page.locator('#aad-input').blur();
  await at('AAD emptied');

  // ── Break-it: every preset, both verdict branches, and the replay alarm ──
  await at('break-it before any delivery (neutral chips)');

  const presets = page.locator('.preset-row .btn');
  const presetCount = await presets.count();
  expect(presetCount, 'the break-it panel must offer presets').toBe(4);

  // Matching contexts first: the `chip-ok` "CONTEXTS AGREE" branch.
  await presets.nth(3).click(); // Restore matching contexts
  await page.click('#breakit-run');
  await expect(page.locator('#verdict-chip')).toContainText('CONTEXTS AGREE');
  await expect(page.locator('#breakit-replay')).toBeEnabled();
  await at('break-it: matching contexts, delivery succeeds');

  // The replay, which is the only route to the `chip-alarm` tone.
  await page.click('#breakit-replay');
  await expect(page.locator('#verdict-chip')).toContainText('REPLAY ACCEPTED');
  await expect(page.locator('#verdict-chip')).toHaveClass(/chip-alarm/);
  await at('break-it: replay accepted — alarm verdict');

  // Each mismatch preset in turn, delivered, so the `BINDING HELD` branch and
  // the `cmp-ne` comparison rows render for every kind of divergence.
  for (let i = 0; i < 3; i++) {
    await presets.nth(3).click(); // reset to matching first
    await presets.nth(i).click();
    await page.click('#breakit-run');
    await expect(page.locator('#verdict-chip')).toContainText('BINDING HELD');
    await expect(page.locator('#breakit-replay')).toBeDisabled();
    await at(`break-it: preset ${i + 1} of 3 — binding held`);
  }

  // Editing the side inputs by hand, which is what the panel actually asks for.
  await presets.nth(3).click();
  await page.fill('#rcv-info', 'a completely different application context');
  await page.selectOption('#snd-mode', '2');
  await page.click('#breakit-run');
  await expect(page.locator('#verdict-chip')).toContainText('BINDING HELD');
  await at('break-it: hand-edited receiver info and sender mode');

  // ── The skip link, on screen only while focused ─────────────────────────
  await page.locator('.cl-skip-link').focus();
  await expect(page.locator('.cl-skip-link')).toBeFocused();
  await at('skip link focused');
}
