/**
 * Context binding — the lab's thesis, as tests.
 *
 * The same three primitives produce a DIFFERENT key when any key-schedule
 * input differs, so the real AEAD refuses. Every "rejects" here is the
 * composition holding, not the crypto failing.
 */
import { beforeAll, describe, expect, test } from 'vitest';
import { OpenError } from './aead';
import { bytesToHex, utf8 } from './bytes';
import { AEAD_AES_128_GCM, MODE_AUTH, MODE_BASE, MODE_PSK } from './consts';
import { generateKeyPair, type KeyPair } from './dhkem';
import { type RecipientParams, setupRecipient, setupSender, type SetupResult } from './hpke';

const INFO = utf8('application context v1');
const AAD = utf8('message framing');
const PT = utf8('the plaintext under test');

let recipientKeys: KeyPair;
let senderKeys: KeyPair;
let sender: SetupResult;
let sealed: { ct: Uint8Array };

function openWith(overrides: Partial<RecipientParams>): Promise<Uint8Array> {
  const r = setupRecipient({
    mode: MODE_BASE,
    aeadId: AEAD_AES_128_GCM,
    enc: sender.enc,
    skR: recipientKeys.sk,
    info: INFO,
    ...overrides,
  });
  return r.context.open(AAD, sealed.ct).then((o) => o.pt);
}

beforeAll(async () => {
  recipientKeys = generateKeyPair();
  senderKeys = generateKeyPair();
  sender = setupSender({ mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, pkR: recipientKeys.pk, info: INFO });
  sealed = await sender.context.seal(AAD, PT);
});

describe('context binding (Base mode baseline)', () => {
  test('positive control: matching contexts open the message', async () => {
    const pt = await openWith({});
    expect(bytesToHex(pt)).toBe(bytesToHex(PT));
  });

  test('info differs by one byte → different key → OpenError', async () => {
    await expect(openWith({ info: utf8('application context v2') })).rejects.toThrow(OpenError);
  });

  test('receiver derives a different key when info differs — same shared_secret', () => {
    const rGood = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk, info: INFO,
    });
    const rBad = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk,
      info: utf8('application context v2'),
    });
    // The KEM agrees — the failure is introduced downstream, in the schedule.
    expect(bytesToHex(rBad.kem.sharedSecret)).toBe(bytesToHex(rGood.kem.sharedSecret));
    expect(bytesToHex(rBad.schedule.key)).not.toBe(bytesToHex(rGood.schedule.key));
    expect(bytesToHex(rBad.schedule.baseNonce)).not.toBe(bytesToHex(rGood.schedule.baseNonce));
  });

  test('AAD differs → OpenError (key identical, tag refuses)', async () => {
    const r = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk, info: INFO,
    });
    await expect(r.context.open(utf8('other framing'), sealed.ct)).rejects.toThrow(OpenError);
  });

  test('mode differs on one side only (receiver runs PSK) → OpenError', async () => {
    const psk = { psk: crypto.getRandomValues(new Uint8Array(32)), pskId: utf8('id') };
    const r = setupRecipient({
      mode: MODE_PSK, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk, info: INFO, psk,
    });
    await expect(r.context.open(AAD, sealed.ct)).rejects.toThrow(OpenError);
  });

  test('both sides changed identically → opens (binding is agreement, not a magic string)', async () => {
    const info2 = utf8('entirely different context');
    const s2 = setupSender({ mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, pkR: recipientKeys.pk, info: info2 });
    const sealed2 = await s2.context.seal(AAD, PT);
    const r2 = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: s2.enc, skR: recipientKeys.sk, info: info2,
    });
    const opened = await r2.context.open(AAD, sealed2.ct);
    expect(bytesToHex(opened.pt)).toBe(bytesToHex(PT));
  });

  test('tampered ciphertext (one bit flipped) → OpenError', async () => {
    const r = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk, info: INFO,
    });
    const tampered = sealed.ct.slice();
    tampered[0] ^= 0x01;
    await expect(r.context.open(AAD, tampered)).rejects.toThrow(OpenError);
  });

  test('truncated ciphertext → OpenError', async () => {
    const r = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk, info: INFO,
    });
    await expect(r.context.open(AAD, sealed.ct.slice(0, 8))).rejects.toThrow(OpenError);
  });

  test('tampered enc → different shared_secret → OpenError', async () => {
    const badEnc = sender.enc.slice();
    badEnc[5] ^= 0xff;
    const r = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: badEnc, skR: recipientKeys.sk, info: INFO,
    });
    await expect(r.context.open(AAD, sealed.ct)).rejects.toThrow(OpenError);
  });

  test('out-of-order delivery: receiver at the wrong seq → OpenError', async () => {
    const r = setupRecipient({
      mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk, info: INFO,
    });
    r.context.seq = 1n; // receiver expects message 1, gets message 0
    await expect(r.context.open(AAD, sealed.ct)).rejects.toThrow(OpenError);
  });

  test('replay to a FRESH context opens fine — HPKE has no replay protection (§9.7.3)', async () => {
    const mk = () =>
      setupRecipient({
        mode: MODE_BASE, aeadId: AEAD_AES_128_GCM, enc: sender.enc, skR: recipientKeys.sk, info: INFO,
      });
    const first = await mk().context.open(AAD, sealed.ct);
    const replayed = await mk().context.open(AAD, sealed.ct);
    expect(bytesToHex(replayed.pt)).toBe(bytesToHex(first.pt));
  });
});

describe('context binding (PSK and Auth inputs)', () => {
  test('PSK differs → different secret → OpenError', async () => {
    const pskA = { psk: crypto.getRandomValues(new Uint8Array(32)), pskId: utf8('team key q3') };
    const pskB = { psk: crypto.getRandomValues(new Uint8Array(32)), pskId: utf8('team key q3') };
    const s = setupSender({ mode: MODE_PSK, aeadId: AEAD_AES_128_GCM, pkR: recipientKeys.pk, info: INFO, psk: pskA });
    const sealedPsk = await s.context.seal(AAD, PT);
    const r = setupRecipient({
      mode: MODE_PSK, aeadId: AEAD_AES_128_GCM, enc: s.enc, skR: recipientKeys.sk, info: INFO, psk: pskB,
    });
    await expect(r.context.open(AAD, sealedPsk.ct)).rejects.toThrow(OpenError);
  });

  test('psk_id differs (same psk) → different key_schedule_context → OpenError', async () => {
    const psk = crypto.getRandomValues(new Uint8Array(32));
    const s = setupSender({
      mode: MODE_PSK, aeadId: AEAD_AES_128_GCM, pkR: recipientKeys.pk, info: INFO,
      psk: { psk, pskId: utf8('key-2026-07') },
    });
    const sealedPsk = await s.context.seal(AAD, PT);
    const r = setupRecipient({
      mode: MODE_PSK, aeadId: AEAD_AES_128_GCM, enc: s.enc, skR: recipientKeys.sk, info: INFO,
      psk: { psk, pskId: utf8('key-2026-08') },
    });
    await expect(r.context.open(AAD, sealedPsk.ct)).rejects.toThrow(OpenError);
  });

  test('Auth: receiver checks against the wrong pkS → different shared_secret → OpenError', async () => {
    const impostor = generateKeyPair();
    const s = setupSender({
      mode: MODE_AUTH, aeadId: AEAD_AES_128_GCM, pkR: recipientKeys.pk, info: INFO, skS: senderKeys.sk,
    });
    const sealedAuth = await s.context.seal(AAD, PT);
    const r = setupRecipient({
      mode: MODE_AUTH, aeadId: AEAD_AES_128_GCM, enc: s.enc, skR: recipientKeys.sk, info: INFO,
      pkS: impostor.pk,
    });
    await expect(r.context.open(AAD, sealedAuth.ct)).rejects.toThrow(OpenError);
  });

  test('Auth: matching pkS opens — the second DH share is what authenticates', async () => {
    const s = setupSender({
      mode: MODE_AUTH, aeadId: AEAD_AES_128_GCM, pkR: recipientKeys.pk, info: INFO, skS: senderKeys.sk,
    });
    expect(s.kem.internals.dhSegments).toHaveLength(2);
    const sealedAuth = await s.context.seal(AAD, PT);
    const r = setupRecipient({
      mode: MODE_AUTH, aeadId: AEAD_AES_128_GCM, enc: s.enc, skR: recipientKeys.sk, info: INFO,
      pkS: senderKeys.pk,
    });
    const opened = await r.context.open(AAD, sealedAuth.ct);
    expect(bytesToHex(opened.pt)).toBe(bytesToHex(PT));
  });
});
