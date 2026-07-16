/**
 * DHKEM(X25519, HKDF-SHA256) — RFC 9180 §4.1.
 *
 * The Diffie-Hellman scalar multiplication itself comes from @noble/curves
 * (audited; this lab does not rebuild curve math — crypto-lab-curve-lens does).
 * Everything the KEM adds AROUND the curve — DeriveKeyPair, the kem_context,
 * eae_prk, and the ExtractAndExpand that turns raw DH output into the KEM
 * shared secret — is hand-rolled here with every intermediate exposed.
 */
import { x25519 } from '@noble/curves/ed25519';
import { concatBytes, isAllZero, randomBytes } from './bytes';
import { KEM_SUITE_ID, NSECRET, NPK, NSK } from './consts';
import { labeledExtract, labeledExpand } from './kdf';

export interface KeyPair {
  sk: Uint8Array;
  pk: Uint8Array;
}

export class KemError extends Error {}

function dh(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  if (sk.length !== NSK) throw new KemError(`X25519 private key must be ${NSK} bytes`);
  if (pk.length !== NPK) throw new KemError(`X25519 public key must be ${NPK} bytes`);
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(sk, pk);
  } catch (e) {
    throw new KemError(`X25519 failed: ${(e as Error).message}`);
  }
  // RFC 9180 §7.1.4: senders and recipients MUST check whether the shared
  // secret is the all-zero value and abort if so.
  if (isAllZero(shared)) throw new KemError('X25519 produced the all-zero shared secret');
  return shared;
}

/** DeriveKeyPair(ikm) for X25519 (RFC 9180 §7.1.3). */
export function deriveKeyPair(ikm: Uint8Array): KeyPair {
  if (ikm.length < NSK) throw new KemError(`DeriveKeyPair ikm must be at least ${NSK} bytes`);
  const dkpPrk = labeledExtract(KEM_SUITE_ID, new Uint8Array(0), 'dkp_prk', ikm);
  const sk = labeledExpand(KEM_SUITE_ID, dkpPrk, 'sk', new Uint8Array(0), NSK);
  return { sk, pk: x25519.getPublicKey(sk) };
}

export function generateKeyPair(): KeyPair {
  return deriveKeyPair(randomBytes(NSK));
}

export function publicKeyOf(sk: Uint8Array): Uint8Array {
  return x25519.getPublicKey(sk);
}

/**
 * Every intermediate the KEM computes, so the UI can show the real bytes
 * instead of asserting "a shared secret appears".
 */
export interface KemInternals {
  /** Ephemeral keypair the sender generated for this one encapsulation. */
  skE?: Uint8Array;
  pkE: Uint8Array;
  /** The raw DH outputs, in order — one for Base/PSK, two for Auth/AuthPSK. */
  dhSegments: { label: string; value: Uint8Array }[];
  /** dh = concat(...dhSegments) */
  dhConcat: Uint8Array;
  /** kem_context = enc || pkRm (|| pkSm in Auth modes) */
  kemContext: Uint8Array;
  /** eae_prk = LabeledExtract("", "eae_prk", dh) */
  eaePrk: Uint8Array;
}

export interface EncapResult {
  sharedSecret: Uint8Array;
  enc: Uint8Array;
  internals: KemInternals;
}

function extractAndExpand(dhInput: Uint8Array, kemContext: Uint8Array) {
  const eaePrk = labeledExtract(KEM_SUITE_ID, new Uint8Array(0), 'eae_prk', dhInput);
  const sharedSecret = labeledExpand(KEM_SUITE_ID, eaePrk, 'shared_secret', kemContext, NSECRET);
  return { eaePrk, sharedSecret };
}

/**
 * Encap(pkR) (RFC 9180 §4.1). `ephemeralIkm` makes the ephemeral key
 * deterministic — used by the RFC test vectors and the UI's replayable
 * pipeline; omit it for fresh randomness.
 */
export function encap(pkR: Uint8Array, ephemeralIkm?: Uint8Array): EncapResult {
  const eph = deriveKeyPair(ephemeralIkm ?? randomBytes(NSK));
  const dhOut = dh(eph.sk, pkR);
  const enc = eph.pk;
  const kemContext = concatBytes(enc, pkR);
  const { eaePrk, sharedSecret } = extractAndExpand(dhOut, kemContext);
  return {
    sharedSecret,
    enc,
    internals: {
      skE: eph.sk,
      pkE: eph.pk,
      dhSegments: [{ label: 'DH(skE, pkR)', value: dhOut }],
      dhConcat: dhOut,
      kemContext,
      eaePrk,
    },
  };
}

/** Decap(enc, skR) (RFC 9180 §4.1). */
export function decap(enc: Uint8Array, skR: Uint8Array): EncapResult {
  const pkR = x25519.getPublicKey(skR);
  const dhOut = dh(skR, enc);
  const kemContext = concatBytes(enc, pkR);
  const { eaePrk, sharedSecret } = extractAndExpand(dhOut, kemContext);
  return {
    sharedSecret,
    enc,
    internals: {
      pkE: enc,
      dhSegments: [{ label: 'DH(skR, enc)', value: dhOut }],
      dhConcat: dhOut,
      kemContext,
      eaePrk,
    },
  };
}

/**
 * AuthEncap(pkR, skS) (RFC 9180 §4.1) — the sender's static key contributes a
 * second DH share, which is what lets the recipient check the sender held skS.
 */
export function authEncap(pkR: Uint8Array, skS: Uint8Array, ephemeralIkm?: Uint8Array): EncapResult {
  const eph = deriveKeyPair(ephemeralIkm ?? randomBytes(NSK));
  const pkS = x25519.getPublicKey(skS);
  const dh1 = dh(eph.sk, pkR);
  const dh2 = dh(skS, pkR);
  const dhConcat = concatBytes(dh1, dh2);
  const enc = eph.pk;
  const kemContext = concatBytes(enc, pkR, pkS);
  const { eaePrk, sharedSecret } = extractAndExpand(dhConcat, kemContext);
  return {
    sharedSecret,
    enc,
    internals: {
      skE: eph.sk,
      pkE: eph.pk,
      dhSegments: [
        { label: 'DH(skE, pkR)', value: dh1 },
        { label: 'DH(skS, pkR)', value: dh2 },
      ],
      dhConcat,
      kemContext,
      eaePrk,
    },
  };
}

/** AuthDecap(enc, skR, pkS) (RFC 9180 §4.1). */
export function authDecap(enc: Uint8Array, skR: Uint8Array, pkS: Uint8Array): EncapResult {
  const pkR = x25519.getPublicKey(skR);
  const dh1 = dh(skR, enc);
  const dh2 = dh(skR, pkS);
  const dhConcat = concatBytes(dh1, dh2);
  const kemContext = concatBytes(enc, pkR, pkS);
  const { eaePrk, sharedSecret } = extractAndExpand(dhConcat, kemContext);
  return {
    sharedSecret,
    enc,
    internals: {
      pkE: enc,
      dhSegments: [
        { label: 'DH(skR, enc)', value: dh1 },
        { label: 'DH(skR, pkS)', value: dh2 },
      ],
      dhConcat,
      kemContext,
      eaePrk,
    },
  };
}
