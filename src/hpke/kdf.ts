/**
 * Labeled HKDF-SHA256 (RFC 9180 §4) — hand-rolled label framing over
 * @noble/hashes' audited HKDF Extract/Expand. The framing (version tag,
 * suite_id, label, length prefix) is the domain separation this lab teaches,
 * so it is spelled out here rather than hidden in a library.
 */
import { extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { concatBytes, i2osp, utf8 } from './bytes';

const VERSION_LABEL = utf8('HPKE-v1');

/** LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm) */
export function labeledExtract(
  suiteId: Uint8Array,
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
): Uint8Array {
  const labeledIkm = concatBytes(VERSION_LABEL, suiteId, utf8(label), ikm);
  // noble signature: extract(hash, ikm, salt)
  return extract(sha256, labeledIkm, salt);
}

/** LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L) */
export function labeledExpand(
  suiteId: Uint8Array,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const labeledInfo = concatBytes(i2osp(length, 2), VERSION_LABEL, suiteId, utf8(label), info);
  return expand(sha256, prk, labeledInfo, length);
}

/** The exact byte string LabeledExtract feeds to HKDF — exposed for the UI's byte view. */
export function labeledIkmBytes(suiteId: Uint8Array, label: string, ikm: Uint8Array): Uint8Array {
  return concatBytes(VERSION_LABEL, suiteId, utf8(label), ikm);
}
