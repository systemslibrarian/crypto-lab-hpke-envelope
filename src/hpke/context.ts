/**
 * Encryption context (RFC 9180 §5.2) — Seal/Open with the sequence-number
 * nonce, plus the secret-export interface (§5.3).
 *
 * ComputeNonce(seq) = base_nonce XOR I2OSP(seq, Nn): the nonce is never
 * random and never transmitted — both sides count. The UI's sequence panel
 * renders exactly the values this class computes.
 */
import { aeadOpen, aeadSeal } from './aead';
import { bytesToHex, i2osp, xorBytes } from './bytes';
import { type AeadId, NN } from './consts';
import { labeledExpand } from './kdf';
import type { ScheduleIntermediates } from './keyschedule';

export class MessageLimitError extends Error {
  constructor() {
    super('Message limit reached: seq would overflow the nonce space');
    this.name = 'MessageLimitError';
  }
}

export class SequenceError extends Error {}

/** One Seal/Open record, kept so the UI can show the nonce evolving. */
export interface SealRecord {
  seq: bigint;
  seqBytes: Uint8Array;
  nonce: Uint8Array;
  ct: Uint8Array;
}

const MAX_SEQ = (1n << BigInt(8 * NN)) - 1n;

export class HpkeContext {
  readonly role: 'sender' | 'recipient';
  readonly aeadId: AeadId;
  readonly key: Uint8Array;
  readonly baseNonce: Uint8Array;
  readonly exporterSecret: Uint8Array;
  private readonly suiteId: Uint8Array;
  seq = 0n;

  constructor(role: 'sender' | 'recipient', aeadId: AeadId, schedule: ScheduleIntermediates) {
    this.role = role;
    this.aeadId = aeadId;
    this.key = schedule.key;
    this.baseNonce = schedule.baseNonce;
    this.exporterSecret = schedule.exporterSecret;
    this.suiteId = schedule.suiteId;
  }

  /** ComputeNonce(seq) = base_nonce XOR I2OSP(seq, Nn). */
  computeNonce(seq: bigint = this.seq): Uint8Array {
    if (seq < 0n || seq > MAX_SEQ) throw new SequenceError(`seq out of range: ${seq}`);
    return xorBytes(this.baseNonce, i2osp(seq, NN));
  }

  private incrementSeq(): void {
    if (this.seq >= MAX_SEQ) throw new MessageLimitError();
    this.seq += 1n;
  }

  /** ContextS.Seal(aad, pt) — encrypt at the current seq, then advance it. */
  async seal(aad: Uint8Array, plaintext: Uint8Array): Promise<SealRecord> {
    const seq = this.seq;
    const seqBytes = i2osp(seq, NN);
    const nonce = this.computeNonce(seq);
    const ct = await aeadSeal(this.aeadId, this.key, nonce, aad, plaintext);
    this.incrementSeq();
    return { seq, seqBytes, nonce, ct };
  }

  /**
   * ContextR.Open(aad, ct) — decrypt at the current seq. Throws OpenError on
   * any mismatch (key, nonce, AAD, or tampered ciphertext); the seq advances
   * only after a successful open, per §5.2.
   */
  async open(aad: Uint8Array, ct: Uint8Array): Promise<{ pt: Uint8Array; seq: bigint; nonce: Uint8Array }> {
    const seq = this.seq;
    const nonce = this.computeNonce(seq);
    const pt = await aeadOpen(this.aeadId, this.key, nonce, aad, ct);
    this.incrementSeq();
    return { pt, seq, nonce };
  }

  /** Context.Export(exporter_context, L) = LabeledExpand(exporter_secret, "sec", exporter_context, L) (§5.3). */
  export(exporterContext: Uint8Array, length: number): Uint8Array {
    return labeledExpand(this.suiteId, this.exporterSecret, 'sec', exporterContext, length);
  }

  debugString(): string {
    return `${this.role} ctx key=${bytesToHex(this.key)} base_nonce=${bytesToHex(this.baseNonce)} seq=${this.seq}`;
  }
}
