/**
 * Known-answer tests from RFC 9180 Appendix A (official test-vectors.json of
 * draft-irtf-cfrg-hpke, trimmed to this lab's suites).
 *
 * Covers A.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM) and
 * A.2 (same KEM/KDF, ChaCha20-Poly1305), each in all four modes
 * (Base / PSK / Auth / AuthPSK): key derivation, encapsulation and
 * decapsulation, every key-schedule intermediate, Seal/Open at
 * seq ∈ {0, 1, 2, 255, 256}, and the secret-export interface.
 */
import { describe, expect, test } from 'vitest';
import { bytesToHex, hexToBytes } from './bytes';
import { type AeadId, AEAD_NAMES, type Mode, MODE_NAMES, modeUsesAuth, modeUsesPsk } from './consts';
import { deriveKeyPair } from './dhkem';
import { setupRecipient, setupSender } from './hpke';
import vectors from './vectors/rfc9180.json';

interface VectorEncryption {
  seq: number;
  aad: string;
  ct: string;
  nonce: string;
  pt: string;
}

interface Vector {
  mode: number;
  kem_id: number;
  kdf_id: number;
  aead_id: number;
  info: string;
  ikmR: string;
  ikmE: string;
  ikmS?: string;
  skRm: string;
  skEm: string;
  skSm?: string;
  psk?: string;
  psk_id?: string;
  pkRm: string;
  pkEm: string;
  pkSm?: string;
  enc: string;
  shared_secret: string;
  key_schedule_context: string;
  secret: string;
  key: string;
  base_nonce: string;
  exporter_secret: string;
  encryptions: VectorEncryption[];
  exports: { exporter_context: string; L: number; exported_value: string }[];
}

const vecs = vectors as unknown as Vector[];

for (const v of vecs) {
  const mode = v.mode as Mode;
  const aeadId = v.aead_id as AeadId;
  const appendix = aeadId === 1 ? 'A.1' : 'A.2';
  const psk =
    v.psk !== undefined && v.psk_id !== undefined
      ? { psk: hexToBytes(v.psk), pskId: hexToBytes(v.psk_id) }
      : undefined;

  describe(`RFC 9180 ${appendix}.${v.mode + 1} — mode ${MODE_NAMES[mode]}, ${AEAD_NAMES[aeadId]}`, () => {
    test('DeriveKeyPair(ikmE) → skEm, pkEm', () => {
      const kp = deriveKeyPair(hexToBytes(v.ikmE));
      expect(bytesToHex(kp.sk)).toBe(v.skEm);
      expect(bytesToHex(kp.pk)).toBe(v.pkEm);
    });

    test('DeriveKeyPair(ikmR) → skRm, pkRm', () => {
      const kp = deriveKeyPair(hexToBytes(v.ikmR));
      expect(bytesToHex(kp.sk)).toBe(v.skRm);
      expect(bytesToHex(kp.pk)).toBe(v.pkRm);
    });

    if (modeUsesAuth(mode)) {
      test('DeriveKeyPair(ikmS) → skSm, pkSm', () => {
        const kp = deriveKeyPair(hexToBytes(v.ikmS!));
        expect(bytesToHex(kp.sk)).toBe(v.skSm);
        expect(bytesToHex(kp.pk)).toBe(v.pkSm);
      });
    }

    const sender = () =>
      setupSender({
        mode,
        aeadId,
        pkR: hexToBytes(v.pkRm),
        info: hexToBytes(v.info),
        psk,
        skS: modeUsesAuth(mode) ? hexToBytes(v.skSm!) : undefined,
        ephemeralIkm: hexToBytes(v.ikmE),
      });

    const recipient = () =>
      setupRecipient({
        mode,
        aeadId,
        enc: hexToBytes(v.enc),
        skR: hexToBytes(v.skRm),
        info: hexToBytes(v.info),
        psk,
        pkS: modeUsesAuth(mode) ? hexToBytes(v.pkSm!) : undefined,
      });

    test('Encap → enc, shared_secret', () => {
      const s = sender();
      expect(bytesToHex(s.enc)).toBe(v.enc);
      expect(bytesToHex(s.kem.sharedSecret)).toBe(v.shared_secret);
    });

    test('Decap → shared_secret', () => {
      const r = recipient();
      expect(bytesToHex(r.kem.sharedSecret)).toBe(v.shared_secret);
    });

    test('key schedule: key_schedule_context = mode || psk_id_hash || info_hash', () => {
      const s = sender();
      expect(bytesToHex(s.schedule.keyScheduleContext)).toBe(v.key_schedule_context);
      // The context really is those three pieces, byte for byte.
      expect(
        bytesToHex(s.schedule.modeByte) + bytesToHex(s.schedule.pskIdHash) + bytesToHex(s.schedule.infoHash),
      ).toBe(v.key_schedule_context);
    });

    test('key schedule: secret', () => {
      expect(bytesToHex(sender().schedule.secret)).toBe(v.secret);
    });

    test('key schedule: key, base_nonce, exporter_secret', () => {
      const s = sender();
      expect(bytesToHex(s.schedule.key)).toBe(v.key);
      expect(bytesToHex(s.schedule.baseNonce)).toBe(v.base_nonce);
      expect(bytesToHex(s.schedule.exporterSecret)).toBe(v.exporter_secret);
    });

    test('sender and recipient derive identical contexts', () => {
      const s = sender();
      const r = recipient();
      expect(bytesToHex(r.schedule.key)).toBe(bytesToHex(s.schedule.key));
      expect(bytesToHex(r.schedule.baseNonce)).toBe(bytesToHex(s.schedule.baseNonce));
      expect(bytesToHex(r.schedule.exporterSecret)).toBe(bytesToHex(s.schedule.exporterSecret));
    });

    for (const enc of v.encryptions) {
      test(`Seal at seq=${enc.seq}: nonce = base_nonce XOR seq, ct matches`, async () => {
        const s = sender();
        s.context.seq = BigInt(enc.seq);
        const rec = await s.context.seal(hexToBytes(enc.aad), hexToBytes(enc.pt));
        expect(bytesToHex(rec.nonce)).toBe(enc.nonce);
        expect(bytesToHex(rec.ct)).toBe(enc.ct);
        expect(s.context.seq).toBe(BigInt(enc.seq) + 1n);
      });

      test(`Open at seq=${enc.seq}: recovers the vector plaintext`, async () => {
        const r = recipient();
        r.context.seq = BigInt(enc.seq);
        const out = await r.context.open(hexToBytes(enc.aad), hexToBytes(enc.ct));
        expect(bytesToHex(out.pt)).toBe(enc.pt);
        expect(bytesToHex(out.nonce)).toBe(enc.nonce);
      });
    }

    for (const [i, exp] of v.exports.entries()) {
      test(`Export #${i + 1} (context=${exp.exporter_context || '<empty>'})`, () => {
        const s = sender();
        const value = s.context.export(hexToBytes(exp.exporter_context), exp.L);
        expect(bytesToHex(value)).toBe(exp.exported_value);
        // Recipient exports the same secret — the exporter is context-bound, not role-bound.
        const r = recipient();
        expect(bytesToHex(r.context.export(hexToBytes(exp.exporter_context), exp.L))).toBe(
          exp.exported_value,
        );
      });
    }
  });
}

test('KAT corpus shape: 8 suite configurations, 4 modes × 2 AEADs', () => {
  expect(vecs).toHaveLength(8);
  expect(new Set(vecs.map((v) => `${v.mode}-${v.aead_id}`)).size).toBe(8);
  for (const v of vecs) {
    expect(v.kem_id).toBe(0x0020);
    expect(v.kdf_id).toBe(0x0001);
    expect(modeUsesPsk(v.mode as Mode)).toBe(v.psk !== undefined);
  }
});
