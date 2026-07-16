/**
 * Top-level HPKE setup (RFC 9180 §5.1) — KEM → KeySchedule → Context, for all
 * four modes, returning every intermediate so the UI can draw the pipeline
 * with real bytes.
 */
import {
  authDecap,
  authEncap,
  decap,
  encap,
  type EncapResult,
  KemError,
  publicKeyOf,
} from './dhkem';
import {
  type AeadId,
  type Mode,
  MODE_AUTH,
  MODE_AUTH_PSK,
  MODE_BASE,
  MODE_PSK,
  modeUsesAuth,
  NPK,
} from './consts';
import { HpkeContext } from './context';
import { keySchedule, type PskInput, ScheduleError, type ScheduleIntermediates } from './keyschedule';

export { MODE_BASE, MODE_PSK, MODE_AUTH, MODE_AUTH_PSK };

export interface SenderParams {
  mode: Mode;
  aeadId: AeadId;
  /** Recipient's public key. */
  pkR: Uint8Array;
  info: Uint8Array;
  psk?: PskInput;
  /** Sender's static private key — required in Auth / AuthPSK. */
  skS?: Uint8Array;
  /** Deterministic ephemeral (test vectors / replayable UI); omit for fresh randomness. */
  ephemeralIkm?: Uint8Array;
}

export interface RecipientParams {
  mode: Mode;
  aeadId: AeadId;
  /** The encapsulated key received from the sender. */
  enc: Uint8Array;
  /** Recipient's private key. */
  skR: Uint8Array;
  info: Uint8Array;
  psk?: PskInput;
  /** Sender's static PUBLIC key — required in Auth / AuthPSK. */
  pkS?: Uint8Array;
}

export interface SetupResult {
  enc: Uint8Array;
  context: HpkeContext;
  kem: EncapResult;
  schedule: ScheduleIntermediates;
}

function checkAuthInputs(mode: Mode, key: Uint8Array | undefined, name: string): Uint8Array {
  if (!modeUsesAuth(mode)) {
    if (key !== undefined) {
      throw new ScheduleError(`${name} provided but mode does not authenticate the sender`);
    }
    return new Uint8Array(0);
  }
  if (key === undefined || key.length !== NPK) {
    throw new ScheduleError(`Auth modes require a ${NPK}-byte ${name}`);
  }
  return key;
}

/** SetupBaseS / SetupPSKS / SetupAuthS / SetupAuthPSKS, by mode. */
export function setupSender(params: SenderParams): SetupResult {
  const { mode, aeadId, pkR, info, psk, ephemeralIkm } = params;
  if (pkR.length !== NPK) throw new KemError(`pkR must be ${NPK} bytes`);
  const skS = checkAuthInputs(mode, params.skS, 'skS (sender private key)');
  const kem = modeUsesAuth(mode) ? authEncap(pkR, skS, ephemeralIkm) : encap(pkR, ephemeralIkm);
  const schedule = keySchedule(mode, aeadId, kem.sharedSecret, info, psk);
  return { enc: kem.enc, context: new HpkeContext('sender', aeadId, schedule), kem, schedule };
}

/** SetupBaseR / SetupPSKR / SetupAuthR / SetupAuthPSKR, by mode. */
export function setupRecipient(params: RecipientParams): SetupResult {
  const { mode, aeadId, enc, skR, info, psk } = params;
  if (enc.length !== NPK) throw new KemError(`enc must be ${NPK} bytes`);
  const pkS = checkAuthInputs(mode, params.pkS, 'pkS (sender public key)');
  const kem = modeUsesAuth(mode) ? authDecap(enc, skR, pkS) : decap(enc, skR);
  const schedule = keySchedule(mode, aeadId, kem.sharedSecret, info, psk);
  return { enc, context: new HpkeContext('recipient', aeadId, schedule), kem, schedule };
}

export { publicKeyOf };
