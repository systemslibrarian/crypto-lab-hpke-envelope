/**
 * Ciphersuite constants for the one suite family this lab builds:
 * DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + { AES-128-GCM | ChaCha20-Poly1305 }
 * (RFC 9180 §7).
 */
import { concatBytes, i2osp, utf8 } from './bytes';

export const KEM_ID = 0x0020; // DHKEM(X25519, HKDF-SHA256)
export const KDF_ID = 0x0001; // HKDF-SHA256

export const AEAD_AES_128_GCM = 0x0001;
export const AEAD_CHACHA20_POLY1305 = 0x0003;
export type AeadId = typeof AEAD_AES_128_GCM | typeof AEAD_CHACHA20_POLY1305;

export const AEAD_NAMES: Record<AeadId, string> = {
  [AEAD_AES_128_GCM]: 'AES-128-GCM',
  [AEAD_CHACHA20_POLY1305]: 'ChaCha20-Poly1305',
};

/** AEAD key length Nk (RFC 9180 §7.3). */
export const AEAD_NK: Record<AeadId, number> = {
  [AEAD_AES_128_GCM]: 16,
  [AEAD_CHACHA20_POLY1305]: 32,
};

/** AEAD nonce length Nn — 12 bytes for both suites (RFC 9180 §7.3). */
export const NN = 12;
/** AEAD tag length Nt — 16 bytes for both suites. */
export const NT = 16;
/** KDF output length Nh for HKDF-SHA256. */
export const NH = 32;
/** DHKEM(X25519) sizes: Nsecret, Nenc, Npk, Nsk are all 32. */
export const NSECRET = 32;
export const NPK = 32;
export const NSK = 32;

export const MODE_BASE = 0x00;
export const MODE_PSK = 0x01;
export const MODE_AUTH = 0x02;
export const MODE_AUTH_PSK = 0x03;
export type Mode = typeof MODE_BASE | typeof MODE_PSK | typeof MODE_AUTH | typeof MODE_AUTH_PSK;

export const MODE_NAMES: Record<Mode, string> = {
  [MODE_BASE]: 'Base',
  [MODE_PSK]: 'PSK',
  [MODE_AUTH]: 'Auth',
  [MODE_AUTH_PSK]: 'AuthPSK',
};

export function modeUsesPsk(mode: Mode): boolean {
  return mode === MODE_PSK || mode === MODE_AUTH_PSK;
}

export function modeUsesAuth(mode: Mode): boolean {
  return mode === MODE_AUTH || mode === MODE_AUTH_PSK;
}

/** suite_id = "KEM" || I2OSP(kem_id, 2) — used inside the KEM (RFC 9180 §4.1). */
export const KEM_SUITE_ID = concatBytes(utf8('KEM'), i2osp(KEM_ID, 2));

/** suite_id = "HPKE" || kem_id || kdf_id || aead_id — used by the key schedule (§5.1). */
export function hpkeSuiteId(aeadId: AeadId): Uint8Array {
  return concatBytes(utf8('HPKE'), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(aeadId, 2));
}
