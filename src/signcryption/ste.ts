/**
 * A bounded multi-user Sign-then-Encrypt (StE) teaching construction.
 *
 * This instantiates the generic StE syntax from An, Dodis, and Rabin
 * (EUROCRYPT 2002) with RFC 9180 Base HPKE and strict RFC 8032 Ed25519.
 * It is intentionally an application construction, not a standardized wire
 * format and not a production messaging protocol.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { concatBytes, equalBytes, i2osp, randomBytes, utf8 } from '../hpke/bytes';
import { AEAD_AES_128_GCM, MODE_AUTH, MODE_BASE } from '../hpke/consts';
import { HpkeContext } from '../hpke/context';
import {
  authDecap,
  deriveKeyPair,
  generateKeyPair,
  type KeyPair,
} from '../hpke/dhkem';
import { setupRecipient, setupSender } from '../hpke/hpke';
import { keySchedule } from '../hpke/keyschedule';

const SIGNED_DOMAIN = 'crypto-lab-s01-ste-signed-v1';
const PAYLOAD_DOMAIN = 'crypto-lab-s01-ste-payload-v1';
const STE_INFO_DOMAIN = 'crypto-lab-s01-ste-hpke-info-v1';
const STE_AAD_DOMAIN = 'crypto-lab-s01-ste-hpke-aad-v1';
const AUTH_INFO_DOMAIN = 'crypto-lab-s01-auth-info-v1';
const AUTH_AAD_DOMAIN = 'crypto-lab-s01-auth-aad-v1';

const MAX_ID_BYTES = 96;
const MAX_CONTEXT_BYTES = 512;
const MAX_MESSAGE_BYTES = 4096;

const fatalUtf8 = new TextDecoder('utf-8', { fatal: true });

export interface SigningKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface LessonParty {
  id: string;
  hpke: KeyPair;
  signing: SigningKeyPair;
}

/** The only sender capability needed to create an StE packet. */
export interface SigningSender {
  id: string;
  signing: { secretKey: Uint8Array };
}

/** A recipient record sufficient for encryption, with no recipient secret. */
export interface HpkeEncryptionRecipient {
  id: string;
  hpke: { pk: Uint8Array };
}

/** A recipient record sufficient for decryption, with no sender secret. */
export interface HpkeDecryptionRecipient {
  id: string;
  hpke: { sk: Uint8Array };
}

/** Both recipient capabilities, used only by the compromised-recipient helper. */
export interface HpkeRecipientKeyholder {
  id: string;
  hpke: { pk: Uint8Array; sk: Uint8Array };
}

/** The sender capability needed for an honest RFC 9180 Auth seal. */
export interface HpkeAuthSender {
  id: string;
  hpke: { sk: Uint8Array };
}

/** Identity-to-key records supplied by an authenticated registry, not a packet. */
export interface TrustedSigningIdentity {
  id: string;
  signing: { publicKey: Uint8Array };
}

/** Public sender record used by RFC 9180 Auth receive/KCI paths. */
export interface TrustedHpkeSender {
  id: string;
  hpke: { pk: Uint8Array };
}

export interface PartySeeds {
  hpkeIkm: Uint8Array;
  signingSeed: Uint8Array;
}

export interface StePacket {
  version: 1;
  senderId: string;
  recipientId: string;
  context: string;
  enc: Uint8Array;
  ciphertext: Uint8Array;
}

export interface SignedFields {
  senderId: string;
  recipientId: string;
  context: string;
  message: string;
}

export interface TransferEvidence extends SignedFields {
  signedBytes: Uint8Array;
  signature: Uint8Array;
  senderPublicKey: Uint8Array;
}

export interface DeSigncryptResult {
  accepted: boolean;
  hpkeOpened: boolean;
  signatureValid: boolean;
  bindingsMatch: boolean;
  /** Application plaintext is released only after every check succeeds. */
  fields: SignedFields | null;
  /** Learner-only quarantine view; never treat this as accepted plaintext. */
  diagnosticFields: SignedFields | null;
  evidence: TransferEvidence | null;
  reason: string;
}

export interface EvidenceResult {
  valid: boolean;
  fields: SignedFields | null;
  reason: string;
}

export interface AuthPacket {
  version: 1;
  senderId: string;
  recipientId: string;
  context: string;
  enc: Uint8Array;
  ciphertext: Uint8Array;
}

export interface AuthOpenResult {
  accepted: boolean;
  hpkeOpened: boolean;
  bindingsMatch: boolean;
  message: string;
  reason: string;
}

function clone(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

function readU16(bytes: Uint8Array, offset: number): number {
  if (offset + 2 > bytes.length) throw new Error('truncated tuple field count');
  return bytes[offset] * 0x100 + bytes[offset + 1];
}

function readU32(bytes: Uint8Array, offset: number): number {
  if (offset + 4 > bytes.length) throw new Error('truncated tuple length');
  return (
    bytes[offset] * 0x1000000
    + bytes[offset + 1] * 0x10000
    + bytes[offset + 2] * 0x100
    + bytes[offset + 3]
  );
}

/** Unambiguous domain-separated tuple: domain || 00 || count || (len || value)*. */
export function encodeTuple(domain: string, fields: Uint8Array[]): Uint8Array {
  const prefix = concatBytes(utf8(domain), new Uint8Array([0]), i2osp(fields.length, 2));
  return concatBytes(
    prefix,
    ...fields.map((field) => concatBytes(i2osp(field.length, 4), field)),
  );
}

export function decodeTuple(
  domain: string,
  encoded: Uint8Array,
  expectedFields: number,
): Uint8Array[] {
  const domainBytes = utf8(domain);
  const headerLength = domainBytes.length + 3;
  if (encoded.length < headerLength) throw new Error('truncated tuple header');
  if (!equalBytes(encoded.slice(0, domainBytes.length), domainBytes)) {
    throw new Error('tuple domain mismatch');
  }
  if (encoded[domainBytes.length] !== 0) throw new Error('tuple domain terminator missing');
  const count = readU16(encoded, domainBytes.length + 1);
  if (count !== expectedFields) {
    throw new Error(`tuple field count ${count} does not match expected ${expectedFields}`);
  }

  const fields: Uint8Array[] = [];
  let offset = headerLength;
  for (let i = 0; i < count; i++) {
    const length = readU32(encoded, offset);
    offset += 4;
    if (offset + length > encoded.length) throw new Error(`tuple field ${i} is truncated`);
    fields.push(encoded.slice(offset, offset + length));
    offset += length;
  }
  if (offset !== encoded.length) throw new Error('tuple has trailing bytes');
  return fields;
}

function validateText(label: string, value: string, maximum: number): Uint8Array {
  const bytes = utf8(value);
  if (bytes.length === 0) throw new Error(`${label} must not be empty`);
  if (bytes.length > maximum) throw new Error(`${label} exceeds ${maximum} UTF-8 bytes`);
  return bytes;
}

function validateFields(fields: SignedFields): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  return [
    validateText('sender identity', fields.senderId, MAX_ID_BYTES),
    validateText('recipient identity', fields.recipientId, MAX_ID_BYTES),
    validateText('application context', fields.context, MAX_CONTEXT_BYTES),
    validateText('message', fields.message, MAX_MESSAGE_BYTES),
  ];
}

export function encodeSignedFields(fields: SignedFields): Uint8Array {
  return encodeTuple(SIGNED_DOMAIN, validateFields(fields));
}

export function decodeSignedFields(encoded: Uint8Array): SignedFields {
  const fields = decodeTuple(SIGNED_DOMAIN, encoded, 4).map((field) => fatalUtf8.decode(field));
  const decoded: SignedFields = {
    senderId: fields[0],
    recipientId: fields[1],
    context: fields[2],
    message: fields[3],
  };
  // Apply the same byte limits on receipt and reject non-canonical UTF-8.
  validateFields(decoded);
  if (!equalBytes(encodeSignedFields(decoded), encoded)) {
    throw new Error('signed fields are not canonically encoded');
  }
  return decoded;
}

function encodePayload(signedBytes: Uint8Array, signature: Uint8Array): Uint8Array {
  return encodeTuple(PAYLOAD_DOMAIN, [signedBytes, signature]);
}

function decodePayload(payload: Uint8Array): { signedBytes: Uint8Array; signature: Uint8Array } {
  const [signedBytes, signature] = decodeTuple(PAYLOAD_DOMAIN, payload, 2);
  if (signature.length !== 64) throw new Error('Ed25519 signature must be 64 bytes');
  return { signedBytes, signature };
}

function contextTuple(
  domain: string,
  senderId: string,
  recipientId: string,
  context: string,
): Uint8Array {
  return encodeTuple(domain, [
    validateText('sender identity', senderId, MAX_ID_BYTES),
    validateText('recipient identity', recipientId, MAX_ID_BYTES),
    validateText('application context', context, MAX_CONTEXT_BYTES),
  ]);
}

function steInfo(packet: Pick<StePacket, 'senderId' | 'recipientId' | 'context'>): Uint8Array {
  return contextTuple(STE_INFO_DOMAIN, packet.senderId, packet.recipientId, packet.context);
}

function steAad(packet: Pick<StePacket, 'senderId' | 'recipientId' | 'context'>): Uint8Array {
  return contextTuple(STE_AAD_DOMAIN, packet.senderId, packet.recipientId, packet.context);
}

function authInfo(packet: Pick<AuthPacket, 'senderId' | 'recipientId' | 'context'>): Uint8Array {
  return contextTuple(AUTH_INFO_DOMAIN, packet.senderId, packet.recipientId, packet.context);
}

function authAad(packet: Pick<AuthPacket, 'senderId' | 'recipientId' | 'context'>): Uint8Array {
  return contextTuple(AUTH_AAD_DOMAIN, packet.senderId, packet.recipientId, packet.context);
}

function strictVerify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    // Noble defaults to ZIP-215 verification. This lesson requests the stricter
    // RFC 8032/FIPS 186-5 behavior explicitly, including canonical encodings.
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

export function createParty(id: string, seeds?: PartySeeds): LessonParty {
  validateText('party identity', id, MAX_ID_BYTES);
  if (seeds && (seeds.hpkeIkm.length !== 32 || seeds.signingSeed.length !== 32)) {
    throw new Error('deterministic party seeds must each be exactly 32 bytes');
  }
  const hpke = seeds ? deriveKeyPair(clone(seeds.hpkeIkm)) : generateKeyPair();
  const secretKey = seeds ? clone(seeds.signingSeed) : randomBytes(32);
  return {
    id,
    hpke,
    signing: {
      secretKey,
      publicKey: ed25519.getPublicKey(secretKey),
    },
  };
}

export async function signcrypt(
  sender: SigningSender,
  recipient: HpkeEncryptionRecipient,
  context: string,
  message: string,
  ephemeralIkm?: Uint8Array,
): Promise<StePacket> {
  const fields: SignedFields = {
    senderId: sender.id,
    recipientId: recipient.id,
    context,
    message,
  };
  const signedBytes = encodeSignedFields(fields);
  const signature = ed25519.sign(signedBytes, sender.signing.secretKey);
  const payload = encodePayload(signedBytes, signature);
  const shell = { senderId: sender.id, recipientId: recipient.id, context };
  const setup = setupSender({
    mode: MODE_BASE,
    aeadId: AEAD_AES_128_GCM,
    pkR: recipient.hpke.pk,
    info: steInfo(shell),
    ephemeralIkm,
  });
  const sealed = await setup.context.seal(steAad(shell), payload);
  return {
    version: 1,
    ...shell,
    enc: clone(setup.enc),
    ciphertext: clone(sealed.ct),
  };
}

async function openStePayload(
  packet: StePacket,
  recipient: HpkeDecryptionRecipient,
): Promise<Uint8Array> {
  if (packet.version !== 1) throw new Error('unsupported StE packet version');
  const setup = setupRecipient({
    mode: MODE_BASE,
    aeadId: AEAD_AES_128_GCM,
    enc: packet.enc,
    skR: recipient.hpke.sk,
    info: steInfo(packet),
  });
  const opened = await setup.context.open(steAad(packet), packet.ciphertext);
  return opened.pt;
}

export async function designcrypt(
  packet: StePacket,
  recipient: HpkeDecryptionRecipient,
  expectedSender: TrustedSigningIdentity,
  expectedContext: string,
): Promise<DeSigncryptResult> {
  if (packet.version !== 1) {
    return {
      accepted: false,
      hpkeOpened: false,
      signatureValid: false,
      bindingsMatch: false,
      fields: null,
      diagnosticFields: null,
      evidence: null,
      reason: 'unsupported StE packet version',
    };
  }
  let payload: Uint8Array;
  try {
    payload = await openStePayload(packet, recipient);
  } catch {
    return {
      accepted: false,
      hpkeOpened: false,
      signatureValid: false,
      bindingsMatch: false,
      fields: null,
      diagnosticFields: null,
      evidence: null,
      reason: 'HPKE Base open failed before signature or identity checks',
    };
  }

  try {
    const { signedBytes, signature } = decodePayload(payload);
    const fields = decodeSignedFields(signedBytes);
    const signatureValid = strictVerify(signature, signedBytes, expectedSender.signing.publicKey);
    const bindingsMatch = (
      packet.senderId === expectedSender.id
      && fields.senderId === packet.senderId
      && fields.recipientId === packet.recipientId
      && fields.context === packet.context
      && packet.recipientId === recipient.id
      && packet.context === expectedContext
    );
    const accepted = signatureValid && bindingsMatch;
    const evidence: TransferEvidence = {
      ...fields,
      signedBytes: clone(signedBytes),
      signature: clone(signature),
      senderPublicKey: clone(expectedSender.signing.publicKey),
    };
    return {
      accepted,
      hpkeOpened: true,
      signatureValid,
      bindingsMatch,
      fields: accepted ? fields : null,
      diagnosticFields: fields,
      evidence: accepted ? evidence : null,
      reason: accepted
        ? 'HPKE opened; strict Ed25519 and all outer/inner bindings agree'
        : !signatureValid
          ? 'HPKE opened, but strict Ed25519 verification failed'
          : 'HPKE opened and the signature verified, but an identity or context binding disagreed',
    };
  } catch {
    return {
      accepted: false,
      hpkeOpened: true,
      signatureValid: false,
      bindingsMatch: false,
      fields: null,
      diagnosticFields: null,
      evidence: null,
      reason: 'HPKE opened, but the signed payload was malformed or non-canonical',
    };
  }
}

export function verifyTransferEvidence(
  evidence: TransferEvidence,
  expectedSender: TrustedSigningIdentity,
  expectedRecipientId: string,
  expectedContext: string,
): EvidenceResult {
  try {
    const fields = decodeSignedFields(evidence.signedBytes);
    const fieldsAgree = (
      fields.senderId === evidence.senderId
      && fields.recipientId === evidence.recipientId
      && fields.context === evidence.context
      && fields.message === evidence.message
    );
    const trustedKeyMatches = (
      evidence.senderId === expectedSender.id
      && fields.senderId === expectedSender.id
      && fields.recipientId === expectedRecipientId
      && fields.context === expectedContext
      && equalBytes(evidence.senderPublicKey, expectedSender.signing.publicKey)
    );
    const valid = (
      fieldsAgree
      && trustedKeyMatches
      && strictVerify(
        evidence.signature,
        evidence.signedBytes,
        expectedSender.signing.publicKey,
      )
    );
    return {
      valid,
      fields: valid ? fields : null,
      reason: valid
        ? 'The disclosed Ed25519 signature verifies under the pinned sender key without the recipient HPKE key'
        : 'The disclosed signature, pinned sender key, or decoded fields do not verify',
    };
  } catch {
    return { valid: false, fields: null, reason: 'The disclosed evidence is malformed' };
  }
}

/** A malicious recipient re-encrypts the exact signed payload to another user. */
export async function forwardToAnotherRecipient(
  packet: StePacket,
  originalRecipient: HpkeDecryptionRecipient,
  newRecipient: HpkeEncryptionRecipient,
  ephemeralIkm?: Uint8Array,
): Promise<StePacket> {
  return rewrapSignedPayload(packet, originalRecipient, newRecipient, {}, ephemeralIkm);
}

/**
 * Adversarial teaching helper: decrypt a valid payload, then encrypt it under
 * an attacker-chosen outer shell. The signature itself is left untouched.
 */
export async function rewrapSignedPayload(
  packet: StePacket,
  originalRecipient: HpkeDecryptionRecipient,
  newRecipient: HpkeEncryptionRecipient,
  shellOverrides: Partial<Pick<StePacket, 'senderId' | 'recipientId' | 'context'>> = {},
  ephemeralIkm?: Uint8Array,
): Promise<StePacket> {
  const payload = await openStePayload(packet, originalRecipient);
  const shell = {
    senderId: shellOverrides.senderId ?? packet.senderId,
    recipientId: shellOverrides.recipientId ?? newRecipient.id,
    context: shellOverrides.context ?? packet.context,
  };
  const setup = setupSender({
    mode: MODE_BASE,
    aeadId: AEAD_AES_128_GCM,
    pkR: newRecipient.hpke.pk,
    info: steInfo(shell),
    ephemeralIkm,
  });
  const sealed = await setup.context.seal(steAad(shell), payload);
  return { version: 1, ...shell, enc: clone(setup.enc), ciphertext: clone(sealed.ct) };
}

/** A compromised recipient changes the message but can only reuse an invalid signature. */
export async function forgeAfterRecipientCompromise(
  packet: StePacket,
  recipient: HpkeRecipientKeyholder,
  replacementMessage: string,
  ephemeralIkm?: Uint8Array,
): Promise<StePacket> {
  const original = decodePayload(await openStePayload(packet, recipient));
  const changed = encodeSignedFields({
    senderId: packet.senderId,
    recipientId: packet.recipientId,
    context: packet.context,
    message: replacementMessage,
  });
  const payload = encodePayload(changed, original.signature);
  const setup = setupSender({
    mode: MODE_BASE,
    aeadId: AEAD_AES_128_GCM,
    pkR: recipient.hpke.pk,
    info: steInfo(packet),
    ephemeralIkm,
  });
  const sealed = await setup.context.seal(steAad(packet), payload);
  return {
    ...packet,
    enc: clone(setup.enc),
    ciphertext: clone(sealed.ct),
  };
}

export function flipSteCiphertext(packet: StePacket): StePacket {
  if (packet.ciphertext.length === 0) throw new Error('cannot flip an empty ciphertext');
  const ciphertext = clone(packet.ciphertext);
  ciphertext[0] ^= 1;
  return { ...packet, enc: clone(packet.enc), ciphertext };
}

export async function authSeal(
  sender: HpkeAuthSender,
  recipient: HpkeEncryptionRecipient,
  context: string,
  message: string,
  ephemeralIkm?: Uint8Array,
): Promise<AuthPacket> {
  validateText('message', message, MAX_MESSAGE_BYTES);
  const shell = { senderId: sender.id, recipientId: recipient.id, context };
  const setup = setupSender({
    mode: MODE_AUTH,
    aeadId: AEAD_AES_128_GCM,
    pkR: recipient.hpke.pk,
    skS: sender.hpke.sk,
    info: authInfo(shell),
    ephemeralIkm,
  });
  const sealed = await setup.context.seal(authAad(shell), utf8(message));
  return {
    version: 1,
    ...shell,
    enc: clone(setup.enc),
    ciphertext: clone(sealed.ct),
  };
}

export async function authOpen(
  packet: AuthPacket,
  recipient: HpkeDecryptionRecipient,
  expectedSender: TrustedHpkeSender,
  expectedContext: string,
): Promise<AuthOpenResult> {
  if (packet.version !== 1) {
    return {
      accepted: false,
      hpkeOpened: false,
      bindingsMatch: false,
      message: '',
      reason: 'unsupported HPKE Auth packet version',
    };
  }
  try {
    const setup = setupRecipient({
      mode: MODE_AUTH,
      aeadId: AEAD_AES_128_GCM,
      enc: packet.enc,
      skR: recipient.hpke.sk,
      pkS: expectedSender.hpke.pk,
      info: authInfo(packet),
    });
    const opened = await setup.context.open(authAad(packet), packet.ciphertext);
    const message = fatalUtf8.decode(opened.pt);
    validateText('message', message, MAX_MESSAGE_BYTES);
    const bindingsMatch = (
      packet.senderId === expectedSender.id
      && packet.recipientId === recipient.id
      && packet.context === expectedContext
    );
    return {
      accepted: bindingsMatch,
      hpkeOpened: true,
      bindingsMatch,
      message: bindingsMatch ? message : '',
      reason: bindingsMatch
        ? 'HPKE Auth opened under the expected public keys and context'
        : 'HPKE Auth opened, but an outer identity or application context did not match the receiver expectation',
    };
  } catch {
    return {
      accepted: false,
      hpkeOpened: false,
      bindingsMatch: false,
      message: '',
      reason: 'HPKE Auth open failed',
    };
  }
}

/**
 * RFC 9180 §9.1.1 KCI attack: after learning skR, an attacker can perform
 * AuthDecap for a fresh valid enc, derive the sender context, and create a
 * ciphertext accepted under pkS without ever using skS.
 */
export async function forgeAuthAfterRecipientCompromise(
  claimedSender: TrustedHpkeSender,
  compromisedRecipient: HpkeDecryptionRecipient,
  context: string,
  message: string,
  ephemeralIkm?: Uint8Array,
): Promise<AuthPacket> {
  validateText('message', message, MAX_MESSAGE_BYTES);
  const shell = {
    senderId: claimedSender.id,
    recipientId: compromisedRecipient.id,
    context,
  };
  const freshEnc = deriveKeyPair(ephemeralIkm ?? randomBytes(32)).pk;
  const kem = authDecap(freshEnc, compromisedRecipient.hpke.sk, claimedSender.hpke.pk);
  const schedule = keySchedule(
    MODE_AUTH,
    AEAD_AES_128_GCM,
    kem.sharedSecret,
    authInfo(shell),
  );
  const attackerContext = new HpkeContext('sender', AEAD_AES_128_GCM, schedule);
  const sealed = await attackerContext.seal(authAad(shell), utf8(message));
  return {
    version: 1,
    ...shell,
    enc: clone(freshEnc),
    ciphertext: clone(sealed.ct),
  };
}

/** RFC 8032's non-canonical S + L mutation used by strict-verification tests. */
export function addEd25519Order(signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) throw new Error('Ed25519 signature must be 64 bytes');
  const out = clone(signature);
  let scalar = 0n;
  for (let i = 63; i >= 32; i--) scalar = (scalar << 8n) | BigInt(out[i]);
  scalar += (1n << 252n) + 27742317777372353535851937790883648493n;
  for (let i = 32; i < 64; i++) {
    out[i] = Number(scalar & 0xffn);
    scalar >>= 8n;
  }
  return out;
}

export function mutateEvidenceSignature(evidence: TransferEvidence): TransferEvidence {
  return { ...evidence, signature: addEd25519Order(evidence.signature) };
}
