/**
 * Fail-closed behavior on malformed and boundary inputs — the edge-case
 * matrix from the build spec. Every rejection here happens BEFORE any
 * ciphertext is produced or accepted.
 */
import { describe, expect, test } from 'vitest';
import { hexToBytes, i2osp, xorBytes } from './bytes';
import { AEAD_AES_128_GCM, MODE_AUTH, MODE_BASE, MODE_PSK } from './consts';
import { deriveKeyPair, generateKeyPair, KemError } from './dhkem';
import { setupRecipient, setupSender } from './hpke';
import { ScheduleError, verifyPskInputs } from './keyschedule';
import { utf8 } from './bytes';

const INFO = utf8('info');

describe('VerifyPSKInputs (RFC 9180 §5.1)', () => {
  const psk32 = { psk: new Uint8Array(32).fill(7), pskId: utf8('id') };

  test('PSK provided in Base mode → ScheduleError', () => {
    expect(() => verifyPskInputs(MODE_BASE, psk32)).toThrow(ScheduleError);
  });

  test('PSK missing in PSK mode → ScheduleError', () => {
    expect(() => verifyPskInputs(MODE_PSK, undefined)).toThrow(ScheduleError);
  });

  test('psk without psk_id → ScheduleError', () => {
    expect(() => verifyPskInputs(MODE_PSK, { psk: new Uint8Array(32).fill(7), pskId: new Uint8Array(0) }))
      .toThrow(ScheduleError);
  });

  test('psk_id without psk → ScheduleError', () => {
    expect(() => verifyPskInputs(MODE_PSK, { psk: new Uint8Array(0), pskId: utf8('id') }))
      .toThrow(ScheduleError);
  });

  test('PSK shorter than 32 bytes → ScheduleError (§9.5 low-entropy guard)', () => {
    expect(() => verifyPskInputs(MODE_PSK, { psk: utf8('hunter2'), pskId: utf8('id') }))
      .toThrow(ScheduleError);
  });

  test('valid PSK inputs pass', () => {
    expect(() => verifyPskInputs(MODE_PSK, psk32)).not.toThrow();
  });
});

describe('KEM input validation', () => {
  test('Auth mode without skS → ScheduleError', () => {
    const r = generateKeyPair();
    expect(() =>
      setupSender({ mode: MODE_AUTH, aeadId: AEAD_AES_128_GCM, pkR: r.pk, info: INFO }),
    ).toThrow(ScheduleError);
  });

  test('skS provided in Base mode → ScheduleError (inputs must match the mode)', () => {
    const r = generateKeyPair();
    const s = generateKeyPair();
    expect(() =>
      setupSender({ mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, pkR: r.pk, info: INFO, skS: s.sk }),
    ).toThrow(ScheduleError);
  });

  test('wrong-length pkR → KemError', () => {
    expect(() =>
      setupSender({ mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, pkR: new Uint8Array(16), info: INFO }),
    ).toThrow(KemError);
  });

  test('wrong-length enc → KemError', () => {
    const r = generateKeyPair();
    expect(() =>
      setupRecipient({ mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: new Uint8Array(31), skR: r.sk, info: INFO }),
    ).toThrow(KemError);
  });

  test('low-order recipient public key → all-zero DH is rejected (§7.1.4)', () => {
    // The all-zero point is a low-order X25519 input; DH output is all zeros.
    const lowOrder = new Uint8Array(32);
    expect(() =>
      setupSender({ mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, pkR: lowOrder, info: INFO }),
    ).toThrow(KemError);
  });

  test('DeriveKeyPair rejects short ikm', () => {
    expect(() => deriveKeyPair(hexToBytes('0011'))).toThrow(KemError);
  });
});

describe('nonce arithmetic', () => {
  test('i2osp produces big-endian fixed-width bytes', () => {
    expect([...i2osp(0, 12)]).toEqual(new Array(12).fill(0));
    expect([...i2osp(256, 12)].slice(10)).toEqual([1, 0]);
    expect(() => i2osp(256, 1)).toThrow();
  });

  test('xorBytes demands equal lengths', () => {
    expect(() => xorBytes(new Uint8Array(3), new Uint8Array(4))).toThrow();
  });

  test('seq=0 nonce IS base_nonce; consecutive nonces differ in the low bytes only', () => {
    const r = generateKeyPair();
    const s = setupSender({ mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, pkR: r.pk, info: INFO });
    const n0 = s.context.computeNonce(0n);
    expect([...n0]).toEqual([...s.schedule.baseNonce]);
    const n1 = s.context.computeNonce(1n);
    expect([...n1.slice(0, 11)]).toEqual([...n0.slice(0, 11)]);
    expect(n1[11]).toBe(n0[11] ^ 1);
  });
});
