/**
 * KeySchedule (RFC 9180 §5.1) — the heart of this lab, hand-rolled.
 *
 * HPKE's security lives here: the same KEM shared secret produces a
 * DIFFERENT AEAD key if the mode byte, the psk_id, or the info string
 * changes. Every intermediate is kept and returned so the UI can show the
 * binding byte-for-byte.
 */
import { concatBytes, i2osp } from './bytes';
import {
  AEAD_NK,
  type AeadId,
  hpkeSuiteId,
  type Mode,
  MODE_NAMES,
  modeUsesPsk,
  NH,
  NN,
} from './consts';
import { labeledExtract, labeledExpand } from './kdf';

export class ScheduleError extends Error {}

export interface PskInput {
  psk: Uint8Array;
  pskId: Uint8Array;
}

export interface ScheduleIntermediates {
  suiteId: Uint8Array;
  mode: Mode;
  modeByte: Uint8Array;
  pskIdHash: Uint8Array;
  infoHash: Uint8Array;
  /** key_schedule_context = mode || psk_id_hash || info_hash */
  keyScheduleContext: Uint8Array;
  /** secret = LabeledExtract(shared_secret, "secret", psk) */
  secret: Uint8Array;
  key: Uint8Array;
  baseNonce: Uint8Array;
  exporterSecret: Uint8Array;
}

const EMPTY = new Uint8Array(0);

/**
 * VerifyPSKInputs (RFC 9180 §5.1): a PSK and its id travel together, and
 * only in the modes that use them. Fail closed on every mismatch.
 */
export function verifyPskInputs(mode: Mode, pskInput?: PskInput): void {
  const gotPsk = pskInput !== undefined && pskInput.psk.length > 0;
  const gotPskId = pskInput !== undefined && pskInput.pskId.length > 0;
  if (gotPsk !== gotPskId) {
    throw new ScheduleError('Inconsistent PSK inputs: psk and psk_id must be supplied together');
  }
  if (gotPsk && !modeUsesPsk(mode)) {
    throw new ScheduleError(`PSK input provided when not needed (mode ${MODE_NAMES[mode]})`);
  }
  if (!gotPsk && modeUsesPsk(mode)) {
    throw new ScheduleError(`Missing required PSK input (mode ${MODE_NAMES[mode]})`);
  }
  // RFC 9180 §9.5: HPKE MUST NOT be used with a low-entropy PSK. Entropy is
  // not measurable here, so this implementation fails closed on any PSK
  // shorter than 32 bytes (the spec's minimum-entropy figure).
  if (gotPsk && pskInput.psk.length < 32) {
    throw new ScheduleError('PSK must be at least 32 bytes (RFC 9180 §9.5 low-entropy guard)');
  }
}

/** KeySchedule(mode, shared_secret, info, psk, psk_id) — RFC 9180 §5.1. */
export function keySchedule(
  mode: Mode,
  aeadId: AeadId,
  sharedSecret: Uint8Array,
  info: Uint8Array,
  pskInput?: PskInput,
): ScheduleIntermediates {
  verifyPskInputs(mode, pskInput);
  const psk = pskInput?.psk ?? EMPTY;
  const pskId = pskInput?.pskId ?? EMPTY;

  const suiteId = hpkeSuiteId(aeadId);
  const pskIdHash = labeledExtract(suiteId, EMPTY, 'psk_id_hash', pskId);
  const infoHash = labeledExtract(suiteId, EMPTY, 'info_hash', info);
  const modeByte = i2osp(mode, 1);
  const keyScheduleContext = concatBytes(modeByte, pskIdHash, infoHash);

  const secret = labeledExtract(suiteId, sharedSecret, 'secret', psk);

  const key = labeledExpand(suiteId, secret, 'key', keyScheduleContext, AEAD_NK[aeadId]);
  const baseNonce = labeledExpand(suiteId, secret, 'base_nonce', keyScheduleContext, NN);
  const exporterSecret = labeledExpand(suiteId, secret, 'exp', keyScheduleContext, NH);

  return {
    suiteId,
    mode,
    modeByte,
    pskIdHash,
    infoHash,
    keyScheduleContext,
    secret,
    key,
    baseNonce,
    exporterSecret,
  };
}
