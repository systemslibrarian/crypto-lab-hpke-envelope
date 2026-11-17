/* What "audited" covers for the Noble packages this lab ships.
 *
 * The scope note on the page said the primitives are real "(audited @noble
 * libraries and the browser's WebCrypto)", the README called curves and hashes
 * "the audited" ones, kdf.ts said "@noble/hashes' audited HKDF" and aead.ts
 * said ChaCha runs on "@noble/ciphers (audited; ...)". None gave a version.
 * Each library records its own audit history, and all three are behind the pins
 * here:
 *
 *   @noble/curves  — "at version 2.3.0, in Aug 2026, by [Trail of Bits]"
 *   @noble/hashes  — "at version 1.0.0, in Jan 2022, independently, by [Cure53]"
 *   @noble/ciphers — "at version 1.0.0, in Sep 2024, independently, by [cure53]"
 *
 * with ^2.4.0 pinned for all three.
 */
import { describe, expect, it } from 'vitest';

import curvesReadme from '../../node_modules/@noble/curves/README.md?raw';
import hashesReadme from '../../node_modules/@noble/hashes/README.md?raw';
import ciphersReadme from '../../node_modules/@noble/ciphers/README.md?raw';
import readmeSource from '../../README.md?raw';
import staticsSource from '../ui/statics.ts?raw';
import kdfSource from './kdf.ts?raw';
import aeadSource from './aead.ts?raw';
import pkg from '../../package.json';

const flat = (text: string) => text.replace(/\n\s*\*\s?/g, ' ').replace(/\s+/g, ' ');

describe('the Noble audit claims', () => {
  it('pins versions later than any of the three libraries has audited', () => {
    for (const lib of ['@noble/curves', '@noble/hashes', '@noble/ciphers'] as const) {
      expect(pkg.dependencies[lib], lib).toBe('^2.4.0');
    }
    expect(curvesReadme).toMatch(/at version 2\.3\.0, in Aug 2026, by \[Trail of Bits\]/);
    expect(hashesReadme).toMatch(/at version 1\.0\.0, in Jan 2022, independently, by \[Cure53\]/);
    expect(ciphersReadme).toMatch(/at version 1\.0\.0, in Sep 2024, independently, by \[cure53\]/);
    for (const readme of [curvesReadme, hashesReadme, ciphersReadme]) {
      expect(readme).not.toMatch(/at version 2\.4\.\d+, in [A-Z]/);
    }
  });

  it('no longer calls the shipped packages simply "audited"', () => {
    for (const [name, text] of [
      ['README.md', flat(readmeSource)],
      ['src/ui/statics.ts', flat(staticsSource)],
      ['src/hpke/kdf.ts', flat(kdfSource)],
      ['src/hpke/aead.ts', flat(aeadSource)],
    ] as const) {
      expect(text, name).not.toContain('audited @noble libraries');
      expect(text, name).not.toContain("@noble/hashes' audited HKDF");
      expect(text, name).not.toContain('@noble/ciphers (audited;');
      expect(text, name).not.toContain('the audited `@noble/curves`');
    }
  });

  it('names the audited version wherever a library is described', () => {
    expect(flat(readmeSource)).toContain('at version 2.3.0, in Aug 2026, by [Trail of Bits]');
    expect(flat(readmeSource)).toContain('at version 1.0.0, in Jan 2022, independently, by [Cure53]');
    expect(flat(readmeSource)).toContain('at version 1.0.0, in Sep 2024, independently, by [cure53]');
    expect(flat(kdfSource)).toContain('at version 1.0.0, in Jan 2022, independently, by [Cure53]');
    expect(flat(aeadSource)).toContain('at version 1.0.0, in Sep 2024, independently, by [cure53]');
  });
});
