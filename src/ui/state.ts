/**
 * Session state for the lab. All key material lives in memory for this tab
 * only — nothing is persisted.
 */
import { randomBytes, utf8 } from '../hpke/bytes';
import {
  AEAD_AES_128_GCM,
  type AeadId,
  type Mode,
  MODE_BASE,
  modeUsesAuth,
  modeUsesPsk,
} from '../hpke/consts';
import type { SealRecord } from '../hpke/context';
import { generateKeyPair, type KeyPair } from '../hpke/dhkem';
import { setupSender, type SetupResult } from '../hpke/hpke';

export interface TranscriptEntry extends SealRecord {
  plaintext: string;
  aad: string;
}

type Listener = () => void;

export class LabStore {
  mode: Mode = MODE_BASE;
  aeadId: AeadId = AEAD_AES_128_GCM;
  info = 'ode to a grecian urn';
  aad = 'message framing v1';
  message = 'Beauty is truth, truth beauty.';
  /** Session PSK — 32 random bytes, shared by both sides in PSK modes. */
  psk: Uint8Array = randomBytes(32);
  pskId = 'lab psk 2026-07';
  recipientKeys: KeyPair = generateKeyPair();
  senderKeys: KeyPair = generateKeyPair();
  /**
   * Fixed per "session" so that when the learner flips the mode, every byte
   * that changes in the schedule is attributable to the mode — not to a fresh
   * ephemeral. "New ephemeral" regenerates it.
   */
  ephemeralIkm: Uint8Array = randomBytes(32);

  setup!: SetupResult;
  /** key_schedule_context from before the last recompute, for the byte diff. */
  prevKsc: Uint8Array | null = null;
  prevMode: Mode | null = null;
  transcript: TranscriptEntry[] = [];

  private listeners: Listener[] = [];

  constructor() {
    this.recompute();
  }

  pskInput() {
    return modeUsesPsk(this.mode) ? { psk: this.psk, pskId: utf8(this.pskId) } : undefined;
  }

  recompute(): void {
    const prev = this.setup;
    this.prevKsc = prev ? prev.schedule.keyScheduleContext : null;
    this.prevMode = prev ? prev.schedule.mode : null;
    this.setup = setupSender({
      mode: this.mode,
      aeadId: this.aeadId,
      pkR: this.recipientKeys.pk,
      info: utf8(this.info),
      psk: this.pskInput(),
      skS: modeUsesAuth(this.mode) ? this.senderKeys.sk : undefined,
      ephemeralIkm: this.ephemeralIkm,
    });
    // A new setup is a new context: the sequence restarts, so the transcript
    // of the old context no longer describes live state.
    this.transcript = [];
    this.notify();
  }

  async seal(): Promise<TranscriptEntry> {
    const rec = await this.setup.context.seal(utf8(this.aad), utf8(this.message));
    const entry: TranscriptEntry = { ...rec, plaintext: this.message, aad: this.aad };
    this.transcript.push(entry);
    this.notify();
    return entry;
  }

  newRecipientKey(): void {
    this.recipientKeys = generateKeyPair();
    this.recompute();
  }

  newSenderKey(): void {
    this.senderKeys = generateKeyPair();
    this.recompute();
  }

  newEphemeral(): void {
    this.ephemeralIkm = randomBytes(32);
    this.recompute();
  }

  newPsk(): void {
    this.psk = randomBytes(32);
    this.recompute();
  }

  subscribe(fn: Listener): void {
    this.listeners.push(fn);
  }

  private notify(): void {
    for (const fn of this.listeners) fn();
  }
}
