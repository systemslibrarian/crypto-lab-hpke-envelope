/**
 * Round-trips with fresh random keys: every mode × both AEADs, multi-message
 * ordering, and exporter agreement.
 */
import { describe, expect, test } from 'vitest';
import { bytesToHex, utf8 } from './bytes';
import {
  AEAD_AES_128_GCM,
  AEAD_CHACHA20_POLY1305,
  AEAD_NAMES,
  type AeadId,
  type Mode,
  MODE_AUTH,
  MODE_AUTH_PSK,
  MODE_BASE,
  MODE_NAMES,
  MODE_PSK,
  modeUsesAuth,
  modeUsesPsk,
} from './consts';
import { generateKeyPair } from './dhkem';
import { setupRecipient, setupSender } from './hpke';

const ALL_MODES: Mode[] = [MODE_BASE, MODE_PSK, MODE_AUTH, MODE_AUTH_PSK];
const ALL_AEADS: AeadId[] = [AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305];

function freshPair(mode: Mode, aeadId: AeadId) {
  const recipientKeys = generateKeyPair();
  const senderKeys = generateKeyPair();
  const psk = modeUsesPsk(mode)
    ? { psk: crypto.getRandomValues(new Uint8Array(32)), pskId: utf8('lab psk id') }
    : undefined;
  const info = utf8('crypto-lab-hpke-envelope round trip');
  const s = setupSender({
    mode,
    aeadId,
    pkR: recipientKeys.pk,
    info,
    psk,
    skS: modeUsesAuth(mode) ? senderKeys.sk : undefined,
  });
  const r = setupRecipient({
    mode,
    aeadId,
    enc: s.enc,
    skR: recipientKeys.sk,
    info,
    psk,
    pkS: modeUsesAuth(mode) ? senderKeys.pk : undefined,
  });
  return { s, r };
}

for (const mode of ALL_MODES) {
  for (const aeadId of ALL_AEADS) {
    describe(`round trip — mode ${MODE_NAMES[mode]}, ${AEAD_NAMES[aeadId]}`, () => {
      test('seal then open recovers the plaintext', async () => {
        const { s, r } = freshPair(mode, aeadId);
        const pt = utf8('an envelope, sealed and opened');
        const aad = utf8('framing data');
        const sealed = await s.context.seal(aad, pt);
        const opened = await r.context.open(aad, sealed.ct);
        expect(bytesToHex(opened.pt)).toBe(bytesToHex(pt));
      });

      test('a stream of messages opens in order, nonces all distinct', async () => {
        const { s, r } = freshPair(mode, aeadId);
        const nonces = new Set<string>();
        for (let i = 0; i < 5; i++) {
          const sealed = await s.context.seal(utf8(`aad-${i}`), utf8(`message ${i}`));
          nonces.add(bytesToHex(sealed.nonce));
          const opened = await r.context.open(utf8(`aad-${i}`), sealed.ct);
          expect(new TextDecoder().decode(opened.pt)).toBe(`message ${i}`);
          expect(opened.seq).toBe(BigInt(i));
        }
        expect(nonces.size).toBe(5);
      });

      test('sender and recipient export identical secrets', () => {
        const { s, r } = freshPair(mode, aeadId);
        const a = s.context.export(utf8('response key'), 32);
        const b = r.context.export(utf8('response key'), 32);
        expect(bytesToHex(a)).toBe(bytesToHex(b));
        // ...and a different exporter_context yields a different secret.
        const c = s.context.export(utf8('response nonce'), 32);
        expect(bytesToHex(c)).not.toBe(bytesToHex(a));
      });
    });
  }
}
