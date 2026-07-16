/**
 * Byte-level helpers used by every stage of the HPKE pipeline.
 * Hand-rolled (rather than imported) because the byte layout of labels,
 * lengths, and XOR masks is exactly what this lab exists to expose.
 */

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error(`hex string has odd length: ${clean.length}`);
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('hex string contains non-hex characters');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** I2OSP — big-endian integer-to-octet-string (RFC 8017 §4.1), as used by RFC 9180. */
export function i2osp(n: number | bigint, length: number): Uint8Array {
  let v = BigInt(n);
  if (v < 0n) throw new Error('i2osp: negative input');
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`i2osp: integer too large for ${length} bytes`);
  return out;
}

/** XOR of two equal-length byte strings — the whole nonce-derivation story. */
export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error('xorBytes: length mismatch');
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function isAllZero(a: Uint8Array): boolean {
  let acc = 0;
  for (const b of a) acc |= b;
  return acc === 0;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
