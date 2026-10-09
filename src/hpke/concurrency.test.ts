import { afterEach, describe, expect, test, vi } from 'vitest';
import * as aead from './aead';
import { bytesToHex, utf8 } from './bytes';
import { AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305, AEAD_NAMES, type AeadId, MODE_BASE, NN } from './consts';
import { MessageLimitError } from './context';
import { generateKeyPair } from './dhkem';
import { setupRecipient, setupSender } from './hpke';

const aad = utf8('authenticated framing');
const messages = [utf8('first ordinary message'), utf8('second ordinary message')];
function pair(aeadId: AeadId) {
  const keys = generateKeyPair();
  const info = utf8('concurrency regression');
  const sender = setupSender({ mode: MODE_BASE, aeadId, pkR: keys.pk, info });
  const recipient = setupRecipient({ mode: MODE_BASE, aeadId, enc: sender.enc, skR: keys.sk, info });
  return { s: sender.context, r: recipient.context };
}
afterEach(() => vi.restoreAllMocks());

for (const aeadId of [AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305] as const) {
  describe(`context concurrency — ${AEAD_NAMES[aeadId]}`, () => {
    test('two concurrent seals use consecutive sequences and distinct nonces', async () => {
      const { s, r } = pair(aeadId);
      const records = await Promise.all(messages.map(pt => s.seal(aad, pt)));
      expect(records.map(record => record.seq)).toEqual([0n, 1n]);
      expect(new Set(records.map(record => bytesToHex(record.nonce))).size).toBe(2);
      expect(s.seq).toBe(2n);
      for (const [i, record] of records.entries()) {
        expect((await r.open(aad, record.ct)).pt).toEqual(messages[i]);
      }
    });

    test('two concurrent opens consume consecutive ciphertexts in invocation order', async () => {
      const { s, r } = pair(aeadId);
      const first = await s.seal(aad, messages[0]);
      const second = await s.seal(aad, messages[1]);
      const opened = await Promise.all([r.open(aad, first.ct), r.open(aad, second.ct)]);
      expect(opened.map(record => record.seq)).toEqual([0n, 1n]);
      expect(opened.map(record => record.pt)).toEqual(messages);
      expect(opened.map(record => record.nonce)).toEqual([first.nonce, second.nonce]);
      expect(r.seq).toBe(2n);
    });

    test('a concurrent duplicate fails without consuming the next sequence or poisoning the queue', async () => {
      const { s, r } = pair(aeadId);
      const first = await s.seal(aad, messages[0]);
      const second = await s.seal(aad, messages[1]);
      const results = await Promise.allSettled([
        r.open(aad, first.ct), r.open(aad, first.ct), r.open(aad, second.ct),
      ]);
      expect(results.map(result => result.status)).toEqual(['fulfilled', 'rejected', 'fulfilled']);
      expect(results[1]).toMatchObject({ reason: expect.any(aead.OpenError) });
      expect(results[2]).toMatchObject({ value: { seq: 1n, pt: messages[1] } });
      expect(r.seq).toBe(2n);
    });

    test('a failed open leaves seq unchanged for an already queued valid open', async () => {
      const { s, r } = pair(aeadId);
      const record = await s.seal(aad, messages[0]);
      const results = await Promise.allSettled([
        r.open(utf8('wrong AAD'), record.ct), r.open(aad, record.ct),
      ]);
      expect(results[0]).toMatchObject({ status: 'rejected', reason: expect.any(aead.OpenError) });
      expect(results[1]).toMatchObject({ status: 'fulfilled', value: { seq: 0n, pt: messages[0] } });
      expect(r.seq).toBe(1n);
    });

    test('an AEAD seal failure leaves seq unchanged and does not poison queued seals', async () => {
      const { s, r } = pair(aeadId);
      const error = new Error('injected AEAD failure');
      vi.spyOn(aead, 'aeadSeal').mockRejectedValueOnce(error);
      const results = await Promise.allSettled([s.seal(aad, messages[0]), s.seal(aad, messages[1])]);
      expect(results[0]).toMatchObject({ status: 'rejected', reason: error });
      expect(results[1]).toMatchObject({ status: 'fulfilled', value: { seq: 0n } });
      if (results[1].status !== 'fulfilled') throw new Error('queued seal failed');
      expect((await r.open(aad, results[1].value.ct)).pt).toEqual(messages[1]);
      expect(s.seq).toBe(1n);
    });

    test('queued Seal and Open preserve the message-limit error without wrapping', async () => {
      const { s, r } = pair(aeadId);
      const max = (1n << BigInt(8 * NN)) - 1n;
      s.seq = r.seq = max - 1n;
      const sealed = await Promise.allSettled([s.seal(aad, messages[0]), s.seal(aad, messages[1])]);
      expect(sealed[0]).toMatchObject({ status: 'fulfilled', value: { seq: max - 1n } });
      expect(sealed[1]).toMatchObject({ status: 'rejected', reason: expect.any(MessageLimitError) });
      if (sealed[0].status !== 'fulfilled') throw new Error('last seal failed');
      const ctAtMax = await aead.aeadSeal(aeadId, s.key, s.computeNonce(max), aad, messages[1]);
      const opened = await Promise.allSettled([r.open(aad, sealed[0].value.ct), r.open(aad, ctAtMax)]);
      expect(opened[0]).toMatchObject({ status: 'fulfilled', value: { seq: max - 1n } });
      expect(opened[1]).toMatchObject({ status: 'rejected', reason: expect.any(MessageLimitError) });
      expect(s.seq).toBe(max);
      expect(r.seq).toBe(max);
    });
  });
}
