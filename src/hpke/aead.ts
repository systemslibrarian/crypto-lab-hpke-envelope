/**
 * AEAD stage (RFC 9180 §5.2 / §7.3).
 *
 * The AEAD internals are deliberately NOT rebuilt here — that is
 * crypto-lab-aes-modes / crypto-lab-aegis-gate territory. AES-128-GCM runs on
 * WebCrypto (the browser's native, constant-time implementation) and
 * ChaCha20-Poly1305 on @noble/ciphers (audited; WebCrypto has no ChaCha).
 */
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305, AEAD_NK, type AeadId, NN, NT } from './consts';

/**
 * Deliberately carries no detail beyond "the tag did not verify" — a real
 * AEAD failure is indistinguishable across causes, and so is this one.
 */
export class OpenError extends Error {
  constructor() {
    super('AEAD open failed: authentication tag did not verify');
    this.name = 'OpenError';
  }
}

function checkParams(aeadId: AeadId, key: Uint8Array, nonce: Uint8Array): void {
  if (aeadId !== AEAD_AES_128_GCM && aeadId !== AEAD_CHACHA20_POLY1305) {
    throw new Error(`Unsupported AEAD id: ${aeadId}`);
  }
  if (key.length !== AEAD_NK[aeadId]) {
    throw new Error(`AEAD key must be ${AEAD_NK[aeadId]} bytes, got ${key.length}`);
  }
  if (nonce.length !== NN) {
    throw new Error(`AEAD nonce must be ${NN} bytes, got ${nonce.length}`);
  }
}

async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export async function aeadSeal(
  aeadId: AeadId,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  checkParams(aeadId, key, nonce);
  if (aeadId === AEAD_CHACHA20_POLY1305) {
    return chacha20poly1305(key, nonce, aad).encrypt(plaintext);
  }
  const cryptoKey = await importAesKey(key);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: NT * 8 },
    cryptoKey,
    plaintext as BufferSource,
  );
  return new Uint8Array(ct);
}

export async function aeadOpen(
  aeadId: AeadId,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  checkParams(aeadId, key, nonce);
  if (ciphertext.length < NT) throw new OpenError();
  if (aeadId === AEAD_CHACHA20_POLY1305) {
    try {
      return chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
    } catch {
      throw new OpenError();
    }
  }
  const cryptoKey = await importAesKey(key);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aad as BufferSource, tagLength: NT * 8 },
      cryptoKey,
      ciphertext as BufferSource,
    );
    return new Uint8Array(pt);
  } catch {
    throw new OpenError();
  }
}
