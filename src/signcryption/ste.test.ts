import { ed25519 } from '@noble/curves/ed25519.js';
import { describe, expect, test } from 'vitest';
import { bytesToHex, hexToBytes } from '../hpke/bytes';
import {
  addEd25519Order,
  authOpen,
  authSeal,
  createParty,
  decodeSignedFields,
  decodeTuple,
  designcrypt,
  encodeSignedFields,
  encodeTuple,
  flipSteCiphertext,
  forgeAfterRecipientCompromise,
  forgeAuthAfterRecipientCompromise,
  forwardToAnotherRecipient,
  mutateEvidenceSignature,
  rewrapSignedPayload,
  signcrypt,
  verifyTransferEvidence,
  type LessonParty,
  type PartySeeds,
  type TransferEvidence,
} from './ste';

const fixed = (byte: number): Uint8Array => new Uint8Array(32).fill(byte);
const seeds = (hpke: number, signing: number): PartySeeds => ({
  hpkeIkm: fixed(hpke),
  signingSeed: fixed(signing),
});

const eph = (byte: number): Uint8Array => fixed(byte);

let sara: LessonParty;
let ravi: LessonParty;
let rita: LessonParty;

function resetParties(): void {
  sara = createParty('Sara', seeds(1, 2));
  ravi = createParty('Ravi', seeds(3, 4));
  rita = createParty('Rita', seeds(5, 6));
}

resetParties();

describe('canonical multi-user transcript', () => {
  test('length framing removes concatenation ambiguity', () => {
    const left = encodeTuple('test-domain', [new TextEncoder().encode('ab'), new TextEncoder().encode('c')]);
    const right = encodeTuple('test-domain', [new TextEncoder().encode('a'), new TextEncoder().encode('bc')]);
    expect(bytesToHex(left)).not.toBe(bytesToHex(right));
    expect(decodeTuple('test-domain', left, 2).map(bytesToHex)).toEqual([
      bytesToHex(new TextEncoder().encode('ab')),
      bytesToHex(new TextEncoder().encode('c')),
    ]);
  });

  test('sender, recipient, application context, and message round-trip exactly', () => {
    const fields = {
      senderId: 'Sara',
      recipientId: 'Ravi',
      context: 'registrar.example/grade-release/v1',
      message: 'Result: pass — π 🐈',
    };
    expect(decodeSignedFields(encodeSignedFields(fields))).toEqual(fields);
  });

  test('wrong domains, field counts, truncation, and trailing bytes reject', () => {
    const encoded = encodeTuple('right', [new Uint8Array([1])]);
    expect(() => decodeTuple('wrong', encoded, 1)).toThrow('domain');
    expect(() => decodeTuple('right', encoded, 2)).toThrow('field count');
    expect(() => decodeTuple('right', encoded.slice(0, -1), 1)).toThrow('truncated');
    const trailing = new Uint8Array(encoded.length + 1);
    trailing.set(encoded);
    expect(() => decodeTuple('right', trailing, 1)).toThrow('trailing');
  });
});

describe('strict RFC 8032 Ed25519', () => {
  test('RFC 8032 section 7.1 test 1 matches exactly and S + L rejects', () => {
    const secretKey = hexToBytes(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    );
    const publicKey = hexToBytes(
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    );
    const expected =
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
      + '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';
    const signature = ed25519.sign(new Uint8Array(0), secretKey);
    expect(bytesToHex(signature)).toBe(expected);
    expect(ed25519.verify(signature, new Uint8Array(0), publicKey, { zip215: false })).toBe(true);
    expect(
      ed25519.verify(addEd25519Order(signature), new Uint8Array(0), publicKey, { zip215: false }),
    ).toBe(false);
  });

  test('rejects the small-order identity case that ZIP-215 accepts', () => {
    resetParties();
    // For the identity encoding A = R and S = 0, ZIP-215's cofactored
    // equation accepts any message. Strict mode rejects the small-order key.
    const identity = hexToBytes(`01${'00'.repeat(31)}`);
    const signedBytes = encodeSignedFields({
      senderId: 'Sara',
      recipientId: 'Ravi',
      context: 'strict-verification',
      message: 'must not verify under a small-order key',
    });
    const signature = new Uint8Array(64);
    signature.set(identity);
    expect(ed25519.verify(signature, signedBytes, identity, { zip215: true })).toBe(true);
    expect(ed25519.verify(signature, signedBytes, identity, { zip215: false })).toBe(false);

    const smallOrderSender: LessonParty = {
      ...sara,
      signing: { ...sara.signing, publicKey: identity },
    };
    const evidence: TransferEvidence = {
      senderId: 'Sara',
      recipientId: 'Ravi',
      context: 'strict-verification',
      message: 'must not verify under a small-order key',
      signedBytes,
      signature,
      senderPublicKey: identity,
    };
    expect(verifyTransferEvidence(evidence, smallOrderSender, 'Ravi', 'strict-verification').valid).toBe(false);
  });
});

describe('bounded HPKE Base plus StE construction', () => {
  test('honest packet opens, verifies, and binds every field', async () => {
    resetParties();
    const packet = await signcrypt(sara, ravi, 'grade-release/v1', 'I earned 93.', eph(11));
    const result = await designcrypt(packet, ravi, sara, 'grade-release/v1');
    expect(result).toMatchObject({
      accepted: true,
      hpkeOpened: true,
      signatureValid: true,
      bindingsMatch: true,
    });
    expect(result.fields).toEqual({
      senderId: 'Sara',
      recipientId: 'Ravi',
      context: 'grade-release/v1',
      message: 'I earned 93.',
    });
  });

  test('ciphertext, context, sender, and recipient changes fail closed', async () => {
    resetParties();
    const packet = await signcrypt(sara, ravi, 'course-A', 'office hours', eph(12));
    expect((await designcrypt(flipSteCiphertext(packet), ravi, sara, 'course-A')).hpkeOpened).toBe(false);
    expect((await designcrypt({ ...packet, context: 'course-B' }, ravi, sara, 'course-A')).hpkeOpened).toBe(false);
    expect((await designcrypt({ ...packet, senderId: 'Ada' }, ravi, sara, 'course-A')).hpkeOpened).toBe(false);
    expect((await designcrypt({ ...packet, recipientId: 'Rita' }, ravi, sara, 'course-A')).hpkeOpened).toBe(false);
    expect((await designcrypt(packet, rita, sara, 'course-A')).hpkeOpened).toBe(false);
  });

  test('unsupported StE and Auth packet versions reject before plaintext release', async () => {
    resetParties();
    const ste = await signcrypt(sara, ravi, 'course-A', 'versioned StE', eph(28));
    const unsupportedSte = { ...ste, version: 2 } as unknown as typeof ste;
    expect(await designcrypt(unsupportedSte, ravi, sara, 'course-A')).toMatchObject({
      accepted: false,
      hpkeOpened: false,
      fields: null,
      evidence: null,
      reason: 'unsupported StE packet version',
    });

    const auth = await authSeal(sara, ravi, 'course-A', 'versioned Auth', eph(29));
    const unsupportedAuth = { ...auth, version: 2 } as unknown as typeof auth;
    expect(await authOpen(unsupportedAuth, ravi, sara, 'course-A')).toMatchObject({
      accepted: false,
      hpkeOpened: false,
      message: '',
      reason: 'unsupported HPKE Auth packet version',
    });
  });

  test('recipient compromise reveals plaintext but cannot forge a changed message', async () => {
    resetParties();
    const packet = await signcrypt(sara, ravi, 'course-A', 'original result', eph(13));
    const exposed = await designcrypt(packet, ravi, sara, 'course-A');
    expect(exposed.fields?.message).toBe('original result');
    const forged = await forgeAfterRecipientCompromise(
      packet,
      ravi,
      'attacker changed result',
      eph(14),
    );
    const rejected = await designcrypt(forged, ravi, sara, 'course-A');
    expect(rejected).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      signatureValid: false,
      bindingsMatch: true,
    });
  });

  test('recipient forwarding preserves the signature but the intended recipient rejects', async () => {
    resetParties();
    const packet = await signcrypt(sara, ravi, 'course-A', 'for Ravi only', eph(15));
    const forwarded = await forwardToAnotherRecipient(packet, ravi, rita, eph(16));
    const result = await designcrypt(forwarded, rita, sara, 'course-A');
    expect(result).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      signatureValid: true,
      bindingsMatch: false,
    });
    expect(result.fields).toBeNull();
    expect(result.evidence).toBeNull();
    expect(result.diagnosticFields?.recipientId).toBe('Ravi');
  });

  test('each trusted identity and application-context binding rejects independently', async () => {
    resetParties();
    const packet = await signcrypt(sara, ravi, 'course-A', 'bound transcript', eph(24));

    // An intact, valid packet from course A is still wrong for an application
    // invocation that independently expects course B.
    expect(await designcrypt(packet, ravi, sara, 'course-B')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      signatureValid: true,
      bindingsMatch: false,
      fields: null,
    });

    const changedContext = await rewrapSignedPayload(
      packet,
      ravi,
      ravi,
      { context: 'course-B' },
      eph(25),
    );
    expect(await designcrypt(changedContext, ravi, sara, 'course-B')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      signatureValid: true,
      bindingsMatch: false,
      fields: null,
      diagnosticFields: { context: 'course-A' },
    });

    // Outer sender and trusted record agree on Mallory, but the signed inner
    // identity remains Sara. This isolates inner-to-outer sender binding.
    const relabeledSender = await rewrapSignedPayload(
      packet,
      ravi,
      ravi,
      { senderId: 'Mallory' },
      eph(26),
    );
    const sameKeyWrongSenderId = { id: 'Mallory', signing: sara.signing };
    expect(await designcrypt(relabeledSender, ravi, sameKeyWrongSenderId, 'course-A')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      signatureValid: true,
      bindingsMatch: false,
    });

    // The packet and inner transcript both say Sara, but the trusted registry
    // record says Mallory. This isolates outer-to-registry sender binding.
    expect(await designcrypt(packet, ravi, sameKeyWrongSenderId, 'course-A')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      signatureValid: true,
      bindingsMatch: false,
    });

    // The same recipient key under a different local identity must not make a
    // packet addressed to Ravi acceptable as one addressed to Rita.
    const sameKeyWrongRecipientId: LessonParty = { ...ravi, id: 'Rita' };
    expect(await designcrypt(packet, sameKeyWrongRecipientId, sara, 'course-A')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      signatureValid: true,
      bindingsMatch: false,
    });
  });

  test('sender signing-key compromise permits new authentic-looking messages', async () => {
    resetParties();
    // These narrowed records make the attacker's exact capabilities visible to
    // TypeScript: the sender signing secret and recipient public key only.
    const stolenSigningCapability = {
      id: sara.id,
      signing: { secretKey: sara.signing.secretKey },
    };
    const recipientPublicRecord = {
      id: ravi.id,
      hpke: { pk: ravi.hpke.pk },
    };
    const forged = await signcrypt(
      stolenSigningCapability,
      recipientPublicRecord,
      'course-A',
      'forged after sender compromise',
      eph(17),
    );
    expect((await designcrypt(forged, ravi, sara, 'course-A')).accepted).toBe(true);
    // The sender-side keys still cannot open a packet encrypted to Ravi.
    expect((await designcrypt(forged, sara, sara, 'course-A')).hpkeOpened).toBe(false);
  });

  test('recipient-disclosed evidence verifies without an HPKE private key', async () => {
    resetParties();
    const packet = await signcrypt(sara, ravi, 'course-A', 'transfer this evidence', eph(18));
    const opened = await designcrypt(packet, ravi, sara, 'course-A');
    expect(opened.evidence).not.toBeNull();
    expect(verifyTransferEvidence(opened.evidence!, sara, 'Ravi', 'course-A').valid).toBe(true);
    expect(verifyTransferEvidence(mutateEvidenceSignature(opened.evidence!), sara, 'Ravi', 'course-A').valid).toBe(false);

    const changedMessage: TransferEvidence = { ...opened.evidence!, message: 'different' };
    expect(verifyTransferEvidence(changedMessage, sara, 'Ravi', 'course-A')).toMatchObject({
      valid: false,
      fields: null,
    });
    expect(verifyTransferEvidence(opened.evidence!, sara, 'Rita', 'course-A').valid).toBe(false);
    expect(verifyTransferEvidence(opened.evidence!, sara, 'Ravi', 'course-B').valid).toBe(false);
  });

  test('evidence cannot replace the pinned sender key with an attacker key', async () => {
    resetParties();
    const signedBytes = encodeSignedFields({
      senderId: 'Sara',
      recipientId: 'Ravi',
      context: 'course-A',
      message: 'attacker-authored evidence',
    });
    const substituted: TransferEvidence = {
      senderId: 'Sara',
      recipientId: 'Ravi',
      context: 'course-A',
      message: 'attacker-authored evidence',
      signedBytes,
      signature: ed25519.sign(signedBytes, rita.signing.secretKey),
      senderPublicKey: rita.signing.publicKey,
    };
    expect(verifyTransferEvidence(substituted, sara, 'Ravi', 'course-A')).toMatchObject({ valid: false, fields: null });
  });

  test('empty and oversized fields refuse before encryption', async () => {
    resetParties();
    await expect(signcrypt(sara, ravi, '', 'message', eph(19))).rejects.toThrow('context');
    await expect(signcrypt(sara, ravi, 'ctx', '', eph(19))).rejects.toThrow('message');
    await expect(signcrypt(sara, ravi, 'ctx', 'a'.repeat(4097), eph(19))).rejects.toThrow('4096');
    expect(() => createParty('x'.repeat(97), seeds(7, 8))).toThrow('96');
  });
});

describe('HPKE Auth comparison and recipient-key KCI', () => {
  test('honest HPKE Auth packet opens under the expected keys and context', async () => {
    resetParties();
    const packet = await authSeal(sara, ravi, 'grade-release/v1', 'honest message', eph(21));
    expect(await authOpen(packet, ravi, sara, 'grade-release/v1')).toMatchObject({
      accepted: true,
      hpkeOpened: true,
      bindingsMatch: true,
      message: 'honest message',
    });
  });

  test('compromised skR creates a fresh accepted Auth ciphertext without skS', async () => {
    resetParties();
    const forged = await forgeAuthAfterRecipientCompromise(
      sara,
      ravi,
      'grade-release/v1',
      'forged with recipient skR only',
      eph(22),
    );
    const result = await authOpen(forged, ravi, sara, 'grade-release/v1');
    expect(result).toMatchObject({
      accepted: true,
      hpkeOpened: true,
      message: 'forged with recipient skR only',
    });
  });

  test('an outsider with the wrong recipient secret cannot open Auth', async () => {
    resetParties();
    const honest = await authSeal(sara, ravi, 'grade-release/v1', 'honest', eph(23));
    expect((await authOpen(honest, rita, sara, 'grade-release/v1')).accepted).toBe(false);
  });

  test('Auth does not release plaintext when trusted identities disagree', async () => {
    resetParties();
    const honest = await authSeal(sara, ravi, 'grade-release/v1', 'quarantine me', eph(27));
    const wrongSenderRecord = { id: 'Mallory', hpke: { pk: sara.hpke.pk } };
    expect(await authOpen(honest, ravi, wrongSenderRecord, 'grade-release/v1')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      bindingsMatch: false,
      message: '',
    });
    const wrongRecipientIdentity: LessonParty = { ...ravi, id: 'Rita' };
    expect(await authOpen(honest, wrongRecipientIdentity, sara, 'grade-release/v1')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      bindingsMatch: false,
      message: '',
    });
    expect(await authOpen(honest, ravi, sara, 'different-application/v1')).toMatchObject({
      accepted: false,
      hpkeOpened: true,
      bindingsMatch: false,
      message: '',
    });
  });
});
