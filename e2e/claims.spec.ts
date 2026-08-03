/**
 * FUNCTIONAL claims spec — the load-bearing states of the lab, asserted
 * against the rendered page rather than against the source.
 *
 * Rules this file plays by:
 *  - Wherever possible a headline is checked against a value the PAGE
 *    computed (the key schedule's own hex, the compare rows' own byte
 *    equality) rather than a string we typed here.
 *  - Every counter is checked for INTERNAL CONSISTENCY — the parts have to
 *    sum to the whole (ct = plaintext + tag; key_schedule_context = mode ‖
 *    psk_id_hash ‖ info_hash; nonce = base_nonce XOR I2OSP(seq, 12)).
 *  - Every failure/tamper path the UI offers is driven to its failure state,
 *    and the page must also SAY WHY.
 *
 * The a11y spec is a separate gate; nothing here weakens it.
 */
import { expect, test, type Locator, type Page } from '@playwright/test';

// Reduced motion collapses the pipeline's stage-highlight delays, so seals
// resolve promptly and deterministically. It changes no computed value.
test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
});

const SEAL_RE =
  /^Sealed message #(\d+) — ct is (\d+) bytes \(plaintext (\d+) \+ 16-byte tag; the length is not hidden\)\. Nonce used: ([0-9a-f]{24})\.$/;

const MODE_RADIO = { Base: '#mode-0', PSK: '#mode-1', Auth: '#mode-2', AuthPSK: '#mode-3' } as const;
const AEAD_OPTION = { 'AES-128-GCM': '1', 'ChaCha20-Poly1305': '3' } as const;

interface SealStatus {
  seq: number;
  ctBytes: number;
  ptBytes: number;
  nonce: string;
}

function parseSeal(text: string): SealStatus {
  const m = SEAL_RE.exec(text.trim());
  expect(m, `seal status did not match its documented shape: ${JSON.stringify(text)}`).not.toBeNull();
  return { seq: +m![1], ctBytes: +m![2], ptBytes: +m![3], nonce: m![4] };
}

/** Click Seal and wait for the status line to report the expected sequence number. */
async function seal(page: Page, expectedSeq: number): Promise<SealStatus> {
  await page.locator('#seal-btn').click();
  await expect(page.locator('#seal-status')).toContainText(`Sealed message #${expectedSeq} `, {
    timeout: 20_000,
  });
  return parseSeal((await page.locator('#seal-status').textContent()) ?? '');
}

function xorHex(a: string, b: string): string {
  expect(a.length).toBe(b.length);
  let out = '';
  for (let i = 0; i < a.length; i += 2) {
    out += (parseInt(a.slice(i, i + 2), 16) ^ parseInt(b.slice(i, i + 2), 16))
      .toString(16)
      .padStart(2, '0');
  }
  return out;
}

/** The `<code class="hexblock">` of the stage-internals row whose label contains `label`. */
function hexblock(page: Page, stage: string, label: string): Locator {
  return page.locator(`#${stage} .hexrow`).filter({ hasText: label }).locator('.hexblock');
}

async function hex(page: Page, stage: string, label: string): Promise<string> {
  return ((await hexblock(page, stage, label).textContent()) ?? '').trim();
}

async function openAllDetails(page: Page): Promise<void> {
  await page.evaluate(() =>
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true)),
  );
}

interface NonceRow {
  seq: string;
  seqBytes: string;
  nonce: string;
  ct: string;
  changedBytes: number;
}

async function nonceRows(page: Page): Promise<NonceRow[]> {
  return page.locator('.nonce-table tbody tr').evaluateAll((trs) =>
    trs.map((tr) => {
      const tds = tr.querySelectorAll('td');
      return {
        seq: (tr.querySelector('th')?.textContent ?? '').trim(),
        seqBytes: (tds[0]?.textContent ?? '').trim(),
        nonce: (tds[1]?.textContent ?? '').trim(),
        ct: (tds[2]?.textContent ?? '').trim(),
        changedBytes: tds[1]?.querySelectorAll('mark.byte-changed').length ?? 0,
      };
    }),
  );
}

interface BreakItState {
  crypto: string;
  cryptoTone: string;
  verdict: string;
  verdictTone: string;
  explain: string;
  compare: Record<string, string>;
}

async function readBreakIt(page: Page): Promise<BreakItState> {
  const tone = async (sel: string) =>
    ((await page.locator(sel).getAttribute('class')) ?? '').split(/\s+/).find((c) => c.startsWith('chip-')) ?? '';
  const compare = await page.locator('.compare-kv').evaluate((dl) => {
    const out: Record<string, string> = {};
    const dts = dl.querySelectorAll('dt');
    const dds = dl.querySelectorAll('dd');
    dts.forEach((dt, i) => {
      out[(dt.textContent ?? '').trim()] = (dds[i]?.textContent ?? '').trim();
    });
    return out;
  });
  return {
    crypto: ((await page.locator('#crypto-chip').textContent()) ?? '').trim(),
    cryptoTone: await tone('#crypto-chip'),
    verdict: ((await page.locator('#verdict-chip').textContent()) ?? '').trim(),
    verdictTone: await tone('#verdict-chip'),
    explain: ((await page.locator('.breakit-explain').textContent()) ?? '').trim(),
    compare,
  };
}

const IDENTICAL = '＝ identical on both sides';
const DIFFERS = '≠ differs between the sides';

/**
 * The verdict must agree with the page's OWN computed comparison rows. These
 * two banners are the never-events the panel itself calls out as bugs.
 */
function assertVerdictSelfConsistent(s: BreakItState): void {
  expect(s.verdict).not.toContain('ACCEPTED DESPITE A CONTEXT MISMATCH');
  expect(s.verdict).not.toContain('REJECTED WITH MATCHING CONTEXTS');
  if (s.explain.includes('the receiver computed an unrelated key')) {
    expect(s.compare['AEAD key (from the schedule)']).toBe(DIFFERS);
    expect(s.compare['base_nonce']).toBe(DIFFERS);
  }
  if (s.explain.includes('Both sides derived the same key')) {
    expect(s.compare['AEAD key (from the schedule)']).toBe(IDENTICAL);
    expect(s.compare['base_nonce']).toBe(IDENTICAL);
  }
}

async function runDelivery(page: Page): Promise<BreakItState> {
  await page.locator('#breakit-run').click();
  await expect(page.locator('#crypto-chip')).not.toContainText('no delivery yet', { timeout: 20_000 });
  await expect(page.locator('#breakit-run')).toBeEnabled({ timeout: 20_000 });
  const s = await readBreakIt(page);
  assertVerdictSelfConsistent(s);
  return s;
}

// ---------------------------------------------------------------------------
// 1. The pipeline's headline: a real Seal, with arithmetic that sums.
// ---------------------------------------------------------------------------

test('seal reports a ciphertext length that sums: plaintext bytes + 16-byte tag', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#seal-status')).toHaveText('');

  const message = await page.locator('#msg-input').inputValue();
  const expectedPt = new TextEncoder().encode(message).length;

  const first = await seal(page, 0);
  expect(first.ptBytes).toBe(expectedPt);
  expect(first.ctBytes).toBe(first.ptBytes + 16);

  // The "On the wire" panel renders the same ct independently — its own
  // byte count must match the status line's.
  await expect(page.locator('#stage-output')).toContainText(`ct #0 (${first.ctBytes} B)`);

  const second = await seal(page, 1);
  expect(second.seq).toBe(1);
  expect(second.ctBytes).toBe(second.ptBytes + 16);
  // Same plaintext, same length — and a different nonce.
  expect(second.ctBytes).toBe(first.ctBytes);
  expect(second.nonce).not.toBe(first.nonce);
});

test('the length arithmetic holds for a multi-byte plaintext (UTF-8, not UTF-16)', async ({ page }) => {
  await page.goto('.');
  const message = 'café ☕ — beauty is truth';
  const expectedPt = new TextEncoder().encode(message).length;
  expect(expectedPt).not.toBe(message.length); // the case that used to be miscounted

  await page.locator('#msg-input').fill(message);
  await page.locator('#msg-input').blur();

  const s = await seal(page, 0);
  expect(s.ptBytes).toBe(expectedPt);
  expect(s.ctBytes).toBe(s.ptBytes + 16);
});

// ---------------------------------------------------------------------------
// 2. The nonce counter: nonce = base_nonce XOR I2OSP(seq, 12), row by row.
// ---------------------------------------------------------------------------

test('every nonce table row is base_nonce XOR I2OSP(seq, 12), and the counter agrees', async ({ page }) => {
  await page.goto('.');
  await openAllDetails(page);

  const baseNonce = await hex(page, 'stage-kdf', 'base_nonce = LabeledExpand');
  expect(baseNonce).toHaveLength(24);

  const empty = await nonceRows(page);
  expect(empty).toHaveLength(1); // the base row only
  expect(empty[0].seq).toBe('base');
  expect(empty[0].nonce).toBe(baseNonce);
  await expect(page.locator('#nonce-h ~ p.note[role="status"]')).toContainText(
    'No messages sealed in this context yet',
  );

  const sealed: string[] = [];
  for (let i = 0; i < 3; i++) sealed.push((await seal(page, i)).nonce);

  const rows = await nonceRows(page);
  expect(rows).toHaveLength(4); // base + 3 seals
  expect(rows[0].nonce).toBe(baseNonce);

  for (let i = 1; i < rows.length; i++) {
    const seq = i - 1;
    expect(rows[i].seq).toBe(String(seq));
    // The I2OSP column is a 12-byte big-endian encoding of the row's own seq.
    expect(rows[i].seqBytes).toBe(seq.toString(16).padStart(24, '0'));
    // The whole point of the panel: the parts XOR to the rendered nonce.
    expect(rows[i].nonce).toBe(xorHex(baseNonce, rows[i].seqBytes));
    // …and to the nonce the seal status independently reported.
    expect(rows[i].nonce).toBe(sealed[seq]);
    // Highlighting counts exactly the bytes that really differ from base.
    let differing = 0;
    for (let b = 0; b < 24; b += 2) {
      if (rows[i].nonce.slice(b, b + 2) !== baseNonce.slice(b, b + 2)) differing++;
    }
    expect(rows[i].changedBytes).toBe(differing);
  }
  expect(rows[1].changedBytes).toBe(0); // seq 0 XOR 0 == base_nonce
  expect(rows[2].changedBytes).toBe(1); // seq 1 touches the low byte only

  await expect(page.locator('#nonce-h ~ p.note[role="status"]')).toContainText(
    '3 messages sealed; next Seal will use seq 3',
  );

  // The AEAD stage advertises the nonce the NEXT seal will use — same rule.
  await expect(page.locator('#stage-aead')).toContainText('nonce for next Seal = base_nonce XOR seq(3)');
  expect(await hex(page, 'stage-aead', 'nonce for next Seal')).toBe(
    xorHex(baseNonce, (3).toString(16).padStart(24, '0')),
  );
});

test('changing a context input re-keys the context and resets the sequence', async ({ page }) => {
  await page.goto('.');
  await seal(page, 0);
  await seal(page, 1);
  expect(await nonceRows(page)).toHaveLength(3);

  await page.locator('#info-input').fill('a different application context');
  await page.locator('#info-input').blur();

  await expect(page.locator('#nonce-h ~ p.note[role="status"]')).toContainText(
    'No messages sealed in this context yet',
  );
  expect(await nonceRows(page)).toHaveLength(1);
  await expect(page.locator('#stage-output')).toContainText('press “Seal the message”');
  // Sequence really restarted, not just the table.
  const after = await seal(page, 0);
  expect(after.seq).toBe(0);
});

// ---------------------------------------------------------------------------
// 3. The key schedule: parts that must sum to the whole.
// ---------------------------------------------------------------------------

test('key_schedule_context is exactly mode ‖ psk_id_hash ‖ info_hash, in both panels', async ({ page }) => {
  await page.goto('.');
  await openAllDetails(page);

  const modeByte = await hex(page, 'stage-kdf', 'mode byte');
  const pskIdHash = await hex(page, 'stage-kdf', 'psk_id_hash = LabeledExtract');
  const infoHash = await hex(page, 'stage-kdf', 'info_hash = LabeledExtract');
  const ksc = await hex(page, 'stage-kdf', 'key_schedule_context = mode');

  expect(modeByte).toBe('00'); // Base
  expect(pskIdHash).toHaveLength(64);
  expect(infoHash).toHaveLength(64);
  expect(ksc).toBe(modeByte + pskIdHash + infoHash);
  expect(ksc).toHaveLength(130); // 65 bytes

  // The byte viewer in the modes panel renders the same value, split into the
  // same three labelled segments.
  await expect(page.locator('.byteview-title')).toContainText('(65 bytes)');
  const segs = await page.locator('.byteseg-bytes').allTextContents();
  expect(segs.map((s) => s.length)).toEqual([2, 64, 64]);
  expect(segs.join('')).toBe(ksc);

  const labels = await page.locator('.byteseg-label').allTextContents();
  expect(labels).toEqual(['mode (1 B)', 'psk_id_hash (32 B)', 'info_hash (32 B)']);
});

test('KEM and AEAD stage figures agree with the bytes they claim to describe', async ({ page }) => {
  await page.goto('.');
  await openAllDetails(page);

  // enc is the 32-byte KEM ciphertext, and the wire panel previews that value.
  const enc = await hex(page, 'stage-kem', 'pkE = enc');
  expect(enc).toHaveLength(64);
  await expect(page.locator('#stage-output')).toContainText('enc (KEM ciphertext, 32 B)');
  await expect(page.locator('#stage-output .inline-hex').first()).toHaveText(`${enc.slice(0, 24)}…`);

  // shared_secret is 32 bytes and the pipeline arrow previews it.
  const ss = await hex(page, 'stage-kem', 'shared_secret = LabeledExpand');
  expect(ss).toHaveLength(64);
  await expect(page.locator('.pipe-arrow-value').nth(1)).toHaveText(`${ss.slice(0, 12)}…`);

  // The AEAD key's stated Nk must equal the key it actually printed.
  const keyLabel = (await page.locator('#stage-aead .hexrow-label').first().textContent()) ?? '';
  expect(keyLabel).toContain('Nk of AES-128-GCM');
  const key = await hex(page, 'stage-aead', 'Nk of AES-128-GCM');
  expect(key).toHaveLength(2 * Number(/key \((\d+) bytes/.exec(keyLabel)![1]));
  expect(key).toHaveLength(32); // 16 bytes
  // …and the schedule's `key` is the same value the AEAD stage is using.
  expect(key).toBe(await hex(page, 'stage-kdf', 'key = LabeledExpand'));
});

// ---------------------------------------------------------------------------
// 4. Four modes, one key schedule — the byte diff is the headline.
// ---------------------------------------------------------------------------

test('Base → Auth changes exactly one byte of the schedule context: the mode byte', async ({ page }) => {
  await page.goto('.');
  await openAllDetails(page);
  const infoHashBefore = await hex(page, 'stage-kdf', 'info_hash = LabeledExtract');

  await page.locator(MODE_RADIO.Auth).check();
  await expect(page.locator('.byteview-title')).toContainText('for mode Auth');

  const diff = page.locator('#modes-h ~ p.note[role="status"]');
  await expect(diff).toContainText('1 byte changed versus mode Base');
  await expect(diff).toContainText('the mode byte');
  // Auth adds a second DH, so the summary must also say shared_secret moved.
  await expect(diff).toContainText('The Auth-mode second DH changed shared_secret upstream as well');

  expect(await page.locator('.byteview mark.byte-changed').count()).toBe(1);
  const segMarks = await page
    .locator('.byteseg-bytes')
    .evaluateAll((codes) => codes.map((c) => c.querySelectorAll('mark.byte-changed').length));
  expect(segMarks).toEqual([1, 0, 0]); // mode only; psk_id_hash and info_hash untouched
  expect(await hex(page, 'stage-kdf', 'mode byte')).toBe('02');
  expect(await hex(page, 'stage-kdf', 'info_hash = LabeledExtract')).toBe(infoHashBefore);

  // Auth really runs the second Diffie-Hellman, and the sender key enters the inputs.
  await expect(page.locator('#stage-kem')).toContainText('DH(skE, pkR)');
  await expect(page.locator('#stage-kem')).toContainText('DH(skS, pkR)');
  await expect(page.locator('#stage-kem')).toContainText('kem_context = enc ‖ pkRm ‖ pkSm');
  await expect(page.locator('#stage-input')).toContainText('sender pkS');
});

test('Base → PSK changes the mode byte and all 32 bytes of psk_id_hash', async ({ page }) => {
  await page.goto('.');
  await openAllDetails(page);

  await page.locator(MODE_RADIO.PSK).check();
  const diff = page.locator('#modes-h ~ p.note[role="status"]');
  await expect(diff).toContainText('33 bytes changed versus mode Base');
  await expect(diff).toContainText('the mode byte and psk_id_hash');
  await expect(diff).toContainText('shared_secret is unchanged');

  const segMarks = await page
    .locator('.byteseg-bytes')
    .evaluateAll((codes) => codes.map((c) => c.querySelectorAll('mark.byte-changed').length));
  expect(segMarks).toEqual([1, 32, 0]);
  // The sentence's own count is the number of highlighted bytes.
  expect(segMarks.reduce((a, b) => a + b, 0)).toBe(33);
  expect(await hex(page, 'stage-kdf', 'mode byte')).toBe('01');
  await expect(page.locator('#stage-kdf')).toContainText('secret = LabeledExtract(shared_secret, "secret", psk)');
});

test('the PSK panel appears only in the modes that use a PSK', async ({ page }) => {
  await page.goto('.');
  const psk = page.locator('#psk-controls');
  await expect(psk).toBeHidden();

  await page.locator(MODE_RADIO.PSK).check();
  await expect(psk).toBeVisible();
  const pskHex = page.locator('#psk-hex');
  await expect(pskHex).toHaveText(/^[0-9a-f]{64}$/); // 32 bytes, per the §9.5 guard
  const before = await pskHex.textContent();
  await page.getByRole('button', { name: 'New 32-byte PSK' }).click();
  await expect(pskHex).not.toHaveText(before ?? '');
  await expect(pskHex).toHaveText(/^[0-9a-f]{64}$/);
  await expect(psk).toContainText('refuses any PSK under 32 bytes');

  await page.locator(MODE_RADIO.Auth).check();
  await expect(psk).toBeHidden();
  await page.locator(MODE_RADIO.AuthPSK).check();
  await expect(psk).toBeVisible();
  await page.locator(MODE_RADIO.Base).check();
  await expect(psk).toBeHidden();
});

test('every mode states what it proves and its exact §9.1 limit', async ({ page }) => {
  await page.goto('.');
  const facts = page.locator('.mode-facts');
  for (const [name, sel] of Object.entries(MODE_RADIO)) {
    await page.locator(sel).check();
    await expect(facts.locator('h3')).toHaveText(`Mode ${name}`);
    await expect(facts).toContainText('What it adds:');
    await expect(facts).toContainText('What it proves:');
    await expect(facts).toContainText('The exact limit:');
    await expect(facts).toContainText('§9.1');
  }
  await page.locator(MODE_RADIO.Auth).check();
  await expect(facts).toContainText('Key-compromise impersonation (§9.1.1)');
  await expect(facts).toContainText('an attacker with skR can forge messages');
  await page.locator(MODE_RADIO.Base).check();
  await expect(facts).toContainText('anyone who knows pkR can produce a ciphertext the recipient will accept');
});

// ---------------------------------------------------------------------------
// 5. Every mode × AEAD really seals, and the arithmetic holds for all of them.
// ---------------------------------------------------------------------------

test('all four modes and both AEADs produce a real, self-consistent seal', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('.');
  await openAllDetails(page);
  const expectedPt = new TextEncoder().encode(await page.locator('#msg-input').inputValue()).length;

  for (const [aead, value] of Object.entries(AEAD_OPTION)) {
    await page.locator('#aead-select').selectOption(value);
    await expect(page.locator('#stage-aead .stage-sub')).toHaveText(`${aead} · RFC 9180 §5.2`);
    const expectedNk = aead === 'AES-128-GCM' ? 16 : 32;
    expect((await hex(page, 'stage-aead', `Nk of ${aead}`)).length).toBe(2 * expectedNk);

    for (const [mode, sel] of Object.entries(MODE_RADIO)) {
      await page.locator(sel).check();
      await expect(page.locator('.byteview-title')).toContainText(`for mode ${mode}`);
      const s = await seal(page, 0);
      expect(s.ptBytes, `${mode}/${aead}`).toBe(expectedPt);
      expect(s.ctBytes, `${mode}/${aead}`).toBe(expectedPt + 16);
      const baseNonce = await hex(page, 'stage-kdf', 'base_nonce = LabeledExpand');
      expect(s.nonce, `${mode}/${aead}`).toBe(baseNonce); // seq 0
    }
  }
});

test('regenerating key material moves exactly the bytes downstream of it', async ({ page }) => {
  await page.goto('.');
  await openAllDetails(page);
  const pkR = page.locator('#stage-input .inline-hex').first();
  const enc0 = await hex(page, 'stage-kem', 'pkE = enc');
  const ss0 = await hex(page, 'stage-kem', 'shared_secret = LabeledExpand');
  const info0 = await hex(page, 'stage-kdf', 'info_hash = LabeledExtract');
  const pkR0 = await pkR.textContent();

  await page.getByRole('button', { name: 'New ephemeral randomness' }).click();
  await expect(hexblock(page, 'stage-kem', 'pkE = enc')).not.toHaveText(enc0);
  expect(await hex(page, 'stage-kem', 'shared_secret = LabeledExpand')).not.toBe(ss0);
  // A fresh ephemeral touches neither the recipient key nor the info binding.
  await expect(pkR).toHaveText(pkR0 ?? '');
  expect(await hex(page, 'stage-kdf', 'info_hash = LabeledExtract')).toBe(info0);

  const ss1 = await hex(page, 'stage-kem', 'shared_secret = LabeledExpand');
  await page.getByRole('button', { name: 'New recipient key (pkR)' }).click();
  await expect(pkR).not.toHaveText(pkR0 ?? '');
  expect(await hex(page, 'stage-kem', 'shared_secret = LabeledExpand')).not.toBe(ss1);
  expect(await hex(page, 'stage-kdf', 'info_hash = LabeledExtract')).toBe(info0);
});

// ---------------------------------------------------------------------------
// 6. Break the binding — every failure path, and why.
// ---------------------------------------------------------------------------

test('matching contexts: the AEAD opens and the verdict says the delivery is what HPKE promises', async ({
  page,
}) => {
  await page.goto('.');
  await expect(page.locator('#crypto-chip')).toContainText('no delivery yet');
  await expect(page.locator('#verdict-chip')).toContainText('no delivery yet');
  await expect(page.locator('#breakit-replay')).toBeDisabled();

  const message = await page.locator('#msg-input').inputValue();
  const s = await runDelivery(page);

  expect(s.crypto).toContain('AEAD Open succeeded — plaintext recovered');
  expect(s.verdict).toContain('CONTEXTS AGREE');
  expect(s.verdictTone).toBe('chip-ok');
  // The recovered plaintext is the real one, round-tripped through the AEAD.
  expect(s.explain).toContain(`Recovered plaintext: “${message}”`);
  expect(s.compare).toEqual({
    'KEM shared_secret': IDENTICAL,
    'AEAD key (from the schedule)': IDENTICAL,
    base_nonce: IDENTICAL,
  });
  await expect(page.locator('#breakit-replay')).toBeEnabled();
});

test('tamper path — receiver info: the key schedule diverges and the binding holds', async ({ page }) => {
  await page.goto('.');
  const sndInfo = await page.locator('#snd-info').inputValue();
  await page.getByRole('button', { name: /Flip one character of receiver’s info/ }).click();
  await expect(page.locator('#rcv-info')).not.toHaveValue(sndInfo);
  await expect(page.locator('#snd-info')).toHaveValue(sndInfo); // only one side moved

  const s = await runDelivery(page);
  expect(s.crypto).toContain('AEAD Open failed — the tag did not verify');
  expect(s.verdict).toContain('BINDING HELD');
  expect(s.verdictTone).toBe('chip-ok'); // a refused mismatch is a healthy system
  expect(s.explain).toContain('You changed: info');
  expect(s.explain).toContain('the receiver computed an unrelated key');
  expect(s.explain).toContain('The rejection is not an error in the crypto; it IS the security.');
  // Same KEM secret, different derived key — the schedule is what rejected it.
  expect(s.compare['KEM shared_secret']).toBe(IDENTICAL);
  expect(s.compare['AEAD key (from the schedule)']).toBe(DIFFERS);
  expect(s.compare['base_nonce']).toBe(DIFFERS);
  await expect(page.locator('#breakit-replay')).toBeDisabled();
});

test('tamper path — sender AAD: identical keys, and the tag still refuses', async ({ page }) => {
  await page.goto('.');
  const rcvAad = await page.locator('#rcv-aad').inputValue();
  await page.getByRole('button', { name: /Change the AAD on the sender only/ }).click();
  await expect(page.locator('#snd-aad')).toHaveValue(`${rcvAad} (edited)`);
  await expect(page.locator('#rcv-aad')).toHaveValue(rcvAad);

  const s = await runDelivery(page);
  expect(s.crypto).toContain('AEAD Open failed — the tag did not verify');
  expect(s.verdict).toContain('BINDING HELD');
  expect(s.explain).toContain('You changed: AAD');
  // This path is mechanically different from the info path and must say so.
  expect(s.explain).toContain('Both sides derived the same key, but the AAD is authenticated by the tag');
  expect(s.compare['KEM shared_secret']).toBe(IDENTICAL);
  expect(s.compare['AEAD key (from the schedule)']).toBe(IDENTICAL);
  expect(s.compare['base_nonce']).toBe(IDENTICAL);
});

test('tamper path — mode on one side only: Base vs PSK is refused', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('button', { name: /Switch the mode on one side only/ }).click();
  await expect(page.locator('#snd-mode')).toHaveValue('0');
  await expect(page.locator('#rcv-mode')).toHaveValue('1');

  const s = await runDelivery(page);
  expect(s.crypto).toContain('AEAD Open failed');
  expect(s.verdict).toContain('BINDING HELD');
  expect(s.explain).toContain('You changed: mode');
  expect(s.explain).toContain('the receiver computed an unrelated key');
  // Base and PSK share the KEM, so only the schedule diverges.
  expect(s.compare['KEM shared_secret']).toBe(IDENTICAL);
  expect(s.compare['AEAD key (from the schedule)']).toBe(DIFFERS);
});

test('tamper path — receiver switched to AuthPSK: the KEM itself diverges too', async ({ page }) => {
  await page.goto('.');
  await page.locator('#rcv-mode').selectOption('3');

  const s = await runDelivery(page);
  expect(s.crypto).toContain('AEAD Open failed');
  expect(s.verdict).toContain('BINDING HELD');
  expect(s.explain).toContain('You changed: mode');
  // AuthPSK runs a second DH, so the divergence starts one stage earlier.
  expect(s.compare['KEM shared_secret']).toBe(DIFFERS);
  expect(s.compare['AEAD key (from the schedule)']).toBe(DIFFERS);
  expect(s.compare['base_nonce']).toBe(DIFFERS);
});

test('tamper path — a hand-typed edit to the receiver info is refused just the same', async ({ page }) => {
  await page.goto('.');
  await page.locator('#rcv-info').fill('ode to a grecian urn ');
  const s = await runDelivery(page);
  expect(s.crypto).toContain('AEAD Open failed');
  expect(s.verdict).toContain('BINDING HELD');
  expect(s.explain).toContain('You changed: info');
});

test('restoring matching contexts brings the delivery back to CONTEXTS AGREE', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('button', { name: /Flip one character of receiver’s info/ }).click();
  expect((await runDelivery(page)).verdict).toContain('BINDING HELD');

  await page.getByRole('button', { name: /Restore matching contexts/ }).click();
  await expect(page.locator('#rcv-info')).toHaveValue(await page.locator('#snd-info').inputValue());
  const s = await runDelivery(page);
  expect(s.verdict).toContain('CONTEXTS AGREE');
  expect(s.crypto).toContain('plaintext recovered');
});

test('replay: valid crypto, alarming system — HPKE has no replay protection (§9.7.3)', async ({ page }) => {
  await page.goto('.');
  await runDelivery(page);
  await expect(page.locator('#breakit-replay')).toBeEnabled();

  await page.locator('#breakit-replay').click();
  await expect(page.locator('#verdict-chip')).toContainText('REPLAY ACCEPTED', { timeout: 20_000 });
  await expect(page.locator('#breakit-replay')).toBeEnabled();

  const s = await readBreakIt(page);
  // The two indicators must disagree — that separation is the whole exhibit.
  expect(s.crypto).toContain('the replayed ciphertext is valid crypto');
  expect(s.cryptoTone).toBe('chip-neutral');
  expect(s.verdict).toContain('REPLAY ACCEPTED — nothing in HPKE stopped this');
  expect(s.verdictTone).toBe('chip-alarm');
  expect(s.explain).toContain('RFC 9180 §9.7.3');
  expect(s.explain).toContain('HPKE provides no other replay protection');
  expect(s.explain).toContain('Detecting duplicates is the application’s job');
});

// ---------------------------------------------------------------------------
// 7. README promises a reader can confirm on the page.
// ---------------------------------------------------------------------------

test('every §9.7 non-goal is stated, and each stage links to the lab that owns it', async ({ page }) => {
  await page.goto('.');
  const secs = await page.locator('.nongoal-sec').allTextContents();
  expect(secs).toEqual(['§9.7.1', '§9.7.2', '§9.7.3', '§9.7.4', '§9.7.5', '§9.7.6']);
  expect(await page.locator('.nongoal-card').count()).toBe(6);
  await expect(page.locator('.nongoal-card').nth(3)).toContainText(
    'not forward secret with respect to recipient compromise in ANY mode',
  );

  for (const stage of ['stage-kem', 'stage-kdf', 'stage-aead']) {
    const links = page.locator(`#${stage} .stage-links a`);
    expect(await links.count(), stage).toBeGreaterThan(0);
    for (const href of await links.evaluateAll((as) => as.map((a) => (a as HTMLAnchorElement).href))) {
      expect(href, stage).toMatch(/^https:\/\/systemslibrarian\.github\.io\/crypto-lab-/);
    }
  }

  // Post-quantum panel: named, not built.
  await expect(page.locator('#pq-h')).toContainText('named, not built');
  await expect(page.locator('#pq-h ~ p').first()).toContainText('ML-KEM-768 + X25519 as a hybrid HPKE KEM');
  await expect(page.locator('#scope-h ~ ul')).toContainText('No key-compromise-impersonation build-out');
});

test('the page loads without a runtime error and renders every panel', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text());
  });
  await page.goto('.');
  await expect(page.locator('main.lab-main > section.panel')).toHaveCount(8);
  await expect(page.locator('h1')).toHaveText('HPKE Envelope');
  await seal(page, 0);
  await runDelivery(page);
  expect(errors).toEqual([]);
});
