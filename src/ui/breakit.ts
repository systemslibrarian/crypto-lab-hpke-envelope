/**
 * Break the binding yourself — against the real primitives.
 *
 * The sender seals with its settings; the receiver opens with ITS settings.
 * Any disagreement in info, AAD, or mode makes the real key schedule derive a
 * different key (or the real AEAD refuse the tag). No simulation anywhere.
 *
 * VERDICT SEPARATION (binding constraint A): the cryptographic result and the
 * security verdict are two independent indicators. "AEAD: rejected" beside
 * "Verdict: binding held" — and "AEAD: valid" beside "Verdict: ALARM" for the
 * replay case — is the point of this panel.
 */
import { equalBytes, utf8 } from '../hpke/bytes';
import {
  type AeadId,
  type Mode,
  MODE_AUTH,
  MODE_AUTH_PSK,
  MODE_BASE,
  MODE_NAMES,
  MODE_PSK,
  modeUsesAuth,
  modeUsesPsk,
} from '../hpke/consts';
import { OpenError } from '../hpke/aead';
import { setupRecipient, setupSender, type SetupResult } from '../hpke/hpke';
import { el, setChip } from './dom';
import type { LabStore } from './state';

interface SideState {
  info: string;
  aad: string;
  mode: Mode;
}

interface Delivery {
  enc: Uint8Array;
  ct: Uint8Array;
  senderSetup: SetupResult;
  senderSide: SideState;
  receiverSide: SideState;
}

export function renderBreakIt(store: LabStore): HTMLElement {
  const root = el('section', { class: 'panel panel-breakit', 'aria-labelledby': 'breakit-h' });
  root.append(
    el('h2', { id: 'breakit-h', text: 'Break the binding yourself' }),
    el('p', { class: 'panel-lede' },
      'Below, the sender and the receiver each have their own copy of the context inputs. They start identical. ',
      'Edit either side — one character of info is enough — then deliver a message. The real AEAD decides. ',
      'Watch the two indicators separately: what the crypto returned, and what it means for the system.'),
  );

  const sender: SideState = { info: store.info, aad: store.aad, mode: MODE_BASE };
  const receiver: SideState = { info: store.info, aad: store.aad, mode: MODE_BASE };
  let lastDelivery: Delivery | null = null;

  // ---- Side editors -------------------------------------------------------
  const sideCard = (title: string, side: SideState, prefix: string) => {
    const infoInput = el('input', { type: 'text', id: `${prefix}-info`, value: side.info }) as HTMLInputElement;
    const aadInput = el('input', { type: 'text', id: `${prefix}-aad`, value: side.aad }) as HTMLInputElement;
    const modeSelect = el('select', { id: `${prefix}-mode` }) as HTMLSelectElement;
    for (const m of [MODE_BASE, MODE_PSK, MODE_AUTH, MODE_AUTH_PSK] as Mode[]) {
      modeSelect.append(el('option', { value: String(m), text: MODE_NAMES[m] }));
    }
    infoInput.addEventListener('input', () => { side.info = infoInput.value; });
    aadInput.addEventListener('input', () => { side.aad = aadInput.value; });
    modeSelect.addEventListener('change', () => { side.mode = Number(modeSelect.value) as Mode; });
    const card = el('div', { class: 'side-card' },
      el('h3', { text: title }),
      el('p', { class: 'ctl' }, el('label', { for: `${prefix}-info`, text: 'info' }), infoInput),
      el('p', { class: 'ctl' }, el('label', { for: `${prefix}-aad`, text: 'AAD' }), aadInput),
      el('p', { class: 'ctl' }, el('label', { for: `${prefix}-mode`, text: 'mode' }), modeSelect),
    );
    return { card, infoInput, aadInput, modeSelect };
  };

  const s = sideCard('Sender seals with', sender, 'snd');
  const r = sideCard('Receiver opens with', receiver, 'rcv');
  root.append(el('div', { class: 'sides' }, s.card, r.card));

  // ---- Presets ------------------------------------------------------------
  const syncInputs = () => {
    s.infoInput.value = sender.info; s.aadInput.value = sender.aad; s.modeSelect.value = String(sender.mode);
    r.infoInput.value = receiver.info; r.aadInput.value = receiver.aad; r.modeSelect.value = String(receiver.mode);
  };
  const presets = el('div', { class: 'preset-row', role: 'group', 'aria-label': 'Break-it presets' });
  const preset = (label: string, fn: () => void) => {
    const b = el('button', { type: 'button', class: 'btn', text: label });
    b.addEventListener('click', () => { fn(); syncInputs(); });
    presets.append(b);
  };
  preset('Flip one character of receiver’s info', () => {
    receiver.info = receiver.info.length > 0
      ? receiver.info.slice(0, -1) + (receiver.info.endsWith('!') ? '?' : '!')
      : '!';
  });
  preset('Change the AAD on the sender only', () => { sender.aad = sender.aad + ' (edited)'; });
  preset('Switch the mode on one side only', () => { receiver.mode = receiver.mode === MODE_BASE ? MODE_PSK : MODE_BASE; });
  preset('Restore matching contexts', () => {
    sender.info = store.info; receiver.info = store.info;
    sender.aad = store.aad; receiver.aad = store.aad;
    sender.mode = MODE_BASE; receiver.mode = MODE_BASE;
  });
  root.append(presets);

  // ---- Run + results ------------------------------------------------------
  const runBtn = el('button', { type: 'button', class: 'btn btn-primary', id: 'breakit-run', text: 'Seal → deliver → open' });
  const replayBtn = el('button', { type: 'button', class: 'btn', id: 'breakit-replay', text: 'Replay the last ciphertext to a fresh receiver context' });
  replayBtn.disabled = true;

  const compareRows = el('dl', { class: 'kv compare-kv' });
  const cryptoChip = el('p', { class: 'chip chip-neutral', id: 'crypto-chip' });
  const verdictChip = el('p', { class: 'chip chip-neutral', id: 'verdict-chip' });
  const explain = el('p', { class: 'breakit-explain' });
  const results = el('div', { class: 'breakit-results', role: 'status', 'aria-live': 'polite' },
    compareRows,
    el('div', { class: 'chip-row' },
      el('div', { class: 'chip-slot' }, el('h3', { text: 'Cryptographic result' }), cryptoChip),
      el('div', { class: 'chip-slot' }, el('h3', { text: 'Security verdict' }), verdictChip),
    ),
    explain,
  );
  setChip(cryptoChip, 'neutral', '·', 'no delivery yet');
  setChip(verdictChip, 'neutral', '·', 'no delivery yet');
  root.append(el('div', { class: 'seal-row' }, runBtn, replayBtn), results);

  const buildSide = (side: SideState, role: 'sender' | 'receiver', enc?: Uint8Array): SetupResult => {
    const psk = modeUsesPsk(side.mode) ? { psk: store.psk, pskId: utf8(store.pskId) } : undefined;
    if (role === 'sender') {
      return setupSender({
        mode: side.mode,
        aeadId: store.aeadId as AeadId,
        pkR: store.recipientKeys.pk,
        info: utf8(side.info),
        psk,
        skS: modeUsesAuth(side.mode) ? store.senderKeys.sk : undefined,
      });
    }
    return setupRecipient({
      mode: side.mode,
      aeadId: store.aeadId as AeadId,
      enc: enc!,
      skR: store.recipientKeys.sk,
      info: utf8(side.info),
      psk,
      pkS: modeUsesAuth(side.mode) ? store.senderKeys.pk : undefined,
    });
  };

  const compareRow = (label: string, equal: boolean) => {
    compareRows.append(
      el('dt', { text: label }),
      el('dd', {}, el('span', { class: equal ? 'cmp cmp-eq' : 'cmp cmp-ne', text: equal ? '＝ identical on both sides' : '≠ differs between the sides' })),
    );
  };

  const mismatchList = () => {
    const out: string[] = [];
    if (sender.info !== receiver.info) out.push('info');
    if (sender.aad !== receiver.aad) out.push('AAD');
    if (sender.mode !== receiver.mode) out.push('mode');
    return out;
  };

  runBtn.addEventListener('click', () => {
    void (async () => {
      runBtn.disabled = true;
      compareRows.textContent = '';
      try {
        const sSetup = buildSide(sender, 'sender');
        const sealed = await sSetup.context.seal(utf8(sender.aad), utf8(store.message));
        const rSetup = buildSide(receiver, 'receiver', sSetup.enc);

        compareRow('KEM shared_secret', equalBytes(sSetup.kem.sharedSecret, rSetup.kem.sharedSecret));
        compareRow('AEAD key (from the schedule)', equalBytes(sSetup.schedule.key, rSetup.schedule.key));
        compareRow('base_nonce', equalBytes(sSetup.schedule.baseNonce, rSetup.schedule.baseNonce));

        let opened: Uint8Array | null = null;
        try {
          opened = (await rSetup.context.open(utf8(receiver.aad), sealed.ct)).pt;
        } catch (e) {
          if (!(e instanceof OpenError)) throw e;
        }

        const mismatches = mismatchList();
        lastDelivery = {
          enc: sSetup.enc, ct: sealed.ct, senderSetup: sSetup,
          senderSide: { ...sender }, receiverSide: { ...receiver },
        };
        replayBtn.disabled = !(opened !== null && mismatches.length === 0);

        if (opened !== null) {
          setChip(cryptoChip, 'neutral', '✓', 'AEAD Open succeeded — plaintext recovered');
          if (mismatches.length === 0) {
            setChip(verdictChip, 'ok', '✓', 'CONTEXTS AGREE — delivery is exactly what HPKE promises');
            explain.textContent =
              `Both sides derived the same key from the same inputs, and the tag verified. ` +
              `Recovered plaintext: “${new TextDecoder().decode(opened)}”. Now edit one side and deliver again.`;
          } else {
            // Cryptographically unreachable for these inputs; if it ever shows, it is a bug, not a success.
            setChip(verdictChip, 'alarm', '⚠', 'ACCEPTED DESPITE A CONTEXT MISMATCH — this must never happen');
            explain.textContent =
              'The sides disagreed on ' + mismatches.join(', ') + ' and the AEAD still opened. That would break HPKE’s binding — treat this lab as broken and report it.';
          }
        } else {
          setChip(cryptoChip, 'neutral', '✗', 'AEAD Open failed — the tag did not verify');
          if (mismatches.length > 0) {
            setChip(verdictChip, 'ok', '✓', 'BINDING HELD — the composition refused the mismatch');
            const keyDiverged = !equalBytes(sSetup.schedule.key, rSetup.schedule.key);
            explain.textContent =
              `You changed: ${mismatches.join(', ')}. ` +
              (keyDiverged
                ? 'The key schedule fed that difference into every derived value, so the receiver computed an unrelated key — the same three primitives, a different binding. '
                : 'Both sides derived the same key, but the AAD is authenticated by the tag, so the AEAD refused. ') +
              'The rejection is not an error in the crypto; it IS the security.';
          } else {
            setChip(verdictChip, 'alarm', '⚠', 'REJECTED WITH MATCHING CONTEXTS — unexpected; likely a bug');
            explain.textContent = 'Contexts matched but the open failed. This should not happen — report it.';
          }
        }
      } finally {
        runBtn.disabled = false;
      }
    })();
  });

  replayBtn.addEventListener('click', () => {
    void (async () => {
      if (!lastDelivery) return;
      replayBtn.disabled = true;
      try {
        const d = lastDelivery;
        const freshReceiver = buildSide(d.receiverSide, 'receiver', d.enc);
        let opened: Uint8Array | null = null;
        try {
          opened = (await freshReceiver.context.open(utf8(d.receiverSide.aad), d.ct)).pt;
        } catch (e) {
          if (!(e instanceof OpenError)) throw e;
        }
        if (opened !== null) {
          setChip(cryptoChip, 'neutral', '✓', 'AEAD Open succeeded — the replayed ciphertext is valid crypto');
          setChip(verdictChip, 'alarm', '⚠', 'REPLAY ACCEPTED — nothing in HPKE stopped this');
          explain.textContent =
            'The same ciphertext was delivered a second time to a fresh context and opened perfectly. ' +
            'RFC 9180 §9.7.3: within one context the sequence gives a degree of replay protection, but “HPKE provides no other replay protection.” ' +
            'Detecting duplicates is the application’s job — a green checkmark from the AEAD is not a verdict about the system.';
        } else {
          setChip(cryptoChip, 'neutral', '✗', 'AEAD Open failed');
          setChip(verdictChip, 'neutral', '·', 'replay did not decrypt (context inputs changed since delivery)');
          explain.textContent = 'The replayed ciphertext no longer matches the receiver context inputs.';
        }
      } finally {
        replayBtn.disabled = false;
      }
    })();
  });

  return root;
}
