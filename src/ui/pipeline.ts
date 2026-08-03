/**
 * THE COMPOSITION SURFACE — the headline mechanism.
 *
 * recipient pkR → [KEM: Encaps] → shared_secret → [KDF: KeySchedule] →
 * key + base_nonce + exporter_secret → [AEAD: Seal] → ct
 *
 * Every stage is a real computation whose real intermediates expand in-page,
 * and every stage links out to the lab that teaches that primitive alone.
 */
import { bytesToHex, concatBytes, utf8 } from '../hpke/bytes';
import {
  AEAD_AES_128_GCM,
  AEAD_CHACHA20_POLY1305,
  AEAD_NAMES,
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
import { el, extLink, hexValue, shortHex } from './dom';
import { LABS } from './links';
import type { LabStore } from './state';

const prefersReducedMotion = () =>
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function stageLinks(links: { href: string; label: string }[]): HTMLElement {
  const p = el('p', { class: 'stage-links' }, 'This stage alone: ');
  links.forEach((l, i) => {
    if (i > 0) p.append(' · ');
    p.append(extLink(l.href, l.label));
  });
  return p;
}

function arrow(topLabel: string): { node: HTMLElement; value: HTMLElement } {
  const value = el('code', { class: 'pipe-arrow-value' });
  const node = el(
    'div',
    { class: 'pipe-arrow' },
    el('span', { class: 'pipe-arrow-label', text: topLabel }),
    value,
    el('span', { class: 'pipe-arrow-glyph', 'aria-hidden': 'true', text: '→' }),
  );
  return { node, value };
}

export function renderPipeline(store: LabStore): HTMLElement {
  const root = el('section', { class: 'panel', 'aria-labelledby': 'pipeline-h' });
  root.append(
    el('h2', { id: 'pipeline-h', text: 'The pipeline — three primitives, one envelope' }),
    el('p', { class: 'panel-lede' },
      'This is the whole scheme. A ', el('strong', {}, 'KEM'), ' turns the recipient’s public key into a fresh shared secret, a ',
      el('strong', {}, 'KDF'), ' schedules that secret into AEAD keys bound to your settings below, and an ',
      el('strong', {}, 'AEAD'), ' seals the message. Change any input and watch the bytes downstream of it change; ',
      'expand a stage to see every intermediate value it really computed.'),
  );

  // ---- Controls -----------------------------------------------------------
  const controls = el('div', { class: 'controls' });

  const modeFieldset = el('fieldset', { class: 'ctl-modes' }, el('legend', { text: 'Mode' }));
  const modes: Mode[] = [MODE_BASE, MODE_PSK, MODE_AUTH, MODE_AUTH_PSK];
  for (const m of modes) {
    const id = `mode-${m}`;
    const input = el('input', { type: 'radio', name: 'hpke-mode', id, value: String(m) });
    (input as HTMLInputElement).checked = store.mode === m;
    input.addEventListener('change', () => {
      store.mode = m;
      store.recompute();
    });
    modeFieldset.append(el('span', { class: 'mode-opt' }, input, el('label', { for: id, text: MODE_NAMES[m] })));
  }

  const aeadSelect = el('select', { id: 'aead-select' });
  for (const a of [AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305] as AeadId[]) {
    const opt = el('option', { value: String(a), text: AEAD_NAMES[a] });
    if (store.aeadId === a) opt.selected = true;
    aeadSelect.append(opt);
  }
  aeadSelect.addEventListener('change', () => {
    store.aeadId = Number(aeadSelect.value) as AeadId;
    store.recompute();
  });

  const textInput = (id: string, label: string, value: string, onChange: (v: string) => void) => {
    const input = el('input', { type: 'text', id, value }) as HTMLInputElement;
    input.addEventListener('change', () => onChange(input.value));
    return el('span', { class: 'ctl' }, el('label', { for: id, text: label }), input);
  };

  controls.append(
    modeFieldset,
    el('span', { class: 'ctl' }, el('label', { for: 'aead-select', text: 'AEAD' }), aeadSelect),
    textInput('info-input', 'info (application context)', store.info, (v) => { store.info = v; store.recompute(); }),
    textInput('aad-input', 'AAD (bound, not encrypted)', store.aad, (v) => { store.aad = v; store.recompute(); }),
    textInput('msg-input', 'plaintext message', store.message, (v) => { store.message = v; store.recompute(); }),
  );

  const pskCtl = el('div', { class: 'controls psk-controls', id: 'psk-controls' });
  const pskIdInput = el('input', { type: 'text', id: 'pskid-input', value: store.pskId }) as HTMLInputElement;
  pskIdInput.addEventListener('change', () => { store.pskId = pskIdInput.value; store.recompute(); });
  const newPskBtn = el('button', { type: 'button', class: 'btn', text: 'New 32-byte PSK' });
  newPskBtn.addEventListener('click', () => store.newPsk());
  const pskHex = el('code', { class: 'inline-hex', id: 'psk-hex' });
  pskCtl.append(
    el('span', { class: 'ctl' }, el('label', { for: 'pskid-input', text: 'psk_id (public label)' }), pskIdInput),
    el('span', { class: 'ctl ctl-static' }, el('span', { class: 'ctl-label', text: 'psk (both sides hold it)' }), pskHex, newPskBtn),
    el('p', { class: 'note', text: 'Fail-closed: this lab refuses any PSK under 32 bytes (RFC 9180 §9.5 forbids low-entropy PSKs).' }),
  );

  const keyBtns = el('div', { class: 'controls key-controls' });
  const mkBtn = (label: string, fn: () => void) => {
    const b = el('button', { type: 'button', class: 'btn', text: label });
    b.addEventListener('click', fn);
    return b;
  };
  keyBtns.append(
    mkBtn('New recipient key (pkR)', () => store.newRecipientKey()),
    mkBtn('New sender static key (skS)', () => store.newSenderKey()),
    mkBtn('New ephemeral randomness', () => store.newEphemeral()),
    el('p', { class: 'note', text: 'Keys are generated in this tab and never leave memory. The ephemeral stays fixed while you flip settings, so every byte that changes is attributable to your change — “New ephemeral randomness” redraws it.' }),
  );

  // ---- Diagram ------------------------------------------------------------
  const diagram = el('div', { class: 'pipeline', role: 'group', 'aria-label': 'HPKE pipeline diagram' });

  const inputKv = el('dl', { class: 'kv' });
  const inputCard = el('div', { class: 'stage stage-io', id: 'stage-input' },
    el('h3', { text: 'Inputs' }),
    inputKv,
  );

  const kemDesc = el('p', { class: 'stage-desc' });
  const kemInternals = el('div', { class: 'stage-internals' });
  const kemCard = el('div', { class: 'stage', id: 'stage-kem' },
    el('h3', {}, el('span', { class: 'stage-num', text: '1' }), ' KEM — Encaps'),
    el('p', { class: 'stage-sub', text: 'DHKEM(X25519, HKDF-SHA256) · RFC 9180 §4.1' }),
    kemDesc,
    el('details', { class: 'stage-details' },
      el('summary', { text: 'Show the real intermediates' }),
      kemInternals,
    ),
    stageLinks([
      { href: LABS.kyberVault, label: 'kyber-vault (KEMs)' },
      { href: LABS.curveLens, label: 'curve-lens (X25519)' },
    ]),
  );

  const kdfInternals = el('div', { class: 'stage-internals' });
  const kdfCard = el('div', { class: 'stage', id: 'stage-kdf' },
    el('h3', {}, el('span', { class: 'stage-num', text: '2' }), ' KDF — KeySchedule'),
    el('p', { class: 'stage-sub', text: 'HKDF-SHA256 · RFC 9180 §5.1' }),
    el('p', { class: 'stage-desc', text: 'Binds the shared secret to the mode byte, psk_id, and info — the composition’s security lives in this binding.' }),
    el('details', { class: 'stage-details' },
      el('summary', { text: 'Show the real intermediates' }),
      kdfInternals,
    ),
    stageLinks([{ href: LABS.kdfChain, label: 'kdf-chain (HKDF alone)' }]),
  );

  const aeadSub = el('p', { class: 'stage-sub' });
  const aeadInternals = el('div', { class: 'stage-internals' });
  const aeadCard = el('div', { class: 'stage', id: 'stage-aead' },
    el('h3', {}, el('span', { class: 'stage-num', text: '3' }), ' AEAD — Seal'),
    aeadSub,
    el('p', { class: 'stage-desc', text: 'Encrypts with the scheduled key and nonce, binding the AAD into the authentication tag.' }),
    el('details', { class: 'stage-details' },
      el('summary', { text: 'Show the real intermediates' }),
      aeadInternals,
    ),
    stageLinks([
      { href: LABS.aesModes, label: 'aes-modes (GCM)' },
      { href: LABS.ascon, label: 'ascon' },
      { href: LABS.aegisGate, label: 'aegis-gate' },
    ]),
  );

  const outputKv = el('dl', { class: 'kv' });
  const outputNote = el('p', { class: 'note' });
  const outputCard = el('div', { class: 'stage stage-io', id: 'stage-output' },
    el('h3', { text: 'On the wire' }),
    outputKv,
    outputNote,
  );

  const arrowPkr = arrow('pkR');
  const arrowSs = arrow('shared_secret');
  const arrowKeys = arrow('key · base_nonce · exporter_secret');
  const arrowCt = arrow('enc ‖ ct');
  diagram.append(
    inputCard,
    arrowPkr.node,
    kemCard,
    arrowSs.node,
    kdfCard,
    arrowKeys.node,
    aeadCard,
    arrowCt.node,
    outputCard,
  );

  const sealBtn = el('button', { type: 'button', class: 'btn btn-primary', id: 'seal-btn', text: 'Seal the message' });
  const sealStatus = el('p', { class: 'seal-status', role: 'status', 'aria-live': 'polite', id: 'seal-status' });
  sealBtn.addEventListener('click', () => {
    void (async () => {
      sealBtn.disabled = true;
      const stages = ['stage-kem', 'stage-kdf', 'stage-aead', 'stage-output'];
      const step = prefersReducedMotion() ? 0 : 260;
      for (const id of stages) {
        document.getElementById(id)?.classList.add('stage-active');
        if (step) await new Promise((r) => setTimeout(r, step));
      }
      const entry = await store.seal();
      // The AEAD sealed the UTF-8 encoding, so the arithmetic printed here has
      // to count UTF-8 bytes. `entry.plaintext.length` counts UTF-16 code
      // units, which made the sum wrong for any non-ASCII message ("café ☕"
      // printed "ct is 25 bytes (plaintext 6 + 16-byte tag)").
      const ptBytes = utf8(entry.plaintext).length;
      sealStatus.textContent = `Sealed message #${entry.seq} — ct is ${entry.ct.length} bytes (plaintext ${ptBytes} + 16-byte tag; the length is not hidden). Nonce used: ${bytesToHex(entry.nonce)}.`;
      setTimeout(() => stages.forEach((id) => document.getElementById(id)?.classList.remove('stage-active')), step ? 900 : 0);
      sealBtn.disabled = false;
    })();
  });

  root.append(controls, pskCtl, keyBtns, diagram, el('div', { class: 'seal-row' }, sealBtn, sealStatus));

  // ---- Live refresh -------------------------------------------------------
  const refresh = () => {
    const { setup } = store;
    const kem = setup.kem;
    const sch = setup.schedule;
    const authed = modeUsesAuth(store.mode);
    const pskUsed = modeUsesPsk(store.mode);

    pskCtl.hidden = !pskUsed;
    pskHex.textContent = bytesToHex(store.psk);

    inputKv.textContent = '';
    const kv = (target: Element, term: string, value: string, cls = '') => {
      target.append(el('dt', { text: term }), el('dd', { class: cls }, el('code', { class: 'inline-hex', text: value })));
    };
    kv(inputKv, 'recipient pkR', shortHex(store.recipientKeys.pk, 12));
    if (authed) kv(inputKv, 'sender pkS', shortHex(store.senderKeys.pk, 12));
    if (pskUsed) kv(inputKv, 'psk_id', store.pskId);
    kv(inputKv, 'info', store.info);
    kv(inputKv, 'plaintext', store.message);
    kv(inputKv, 'AAD', store.aad);

    kemDesc.textContent = authed
      ? 'AuthEncap: a fresh ephemeral key plus the sender’s static key — two DH shares. The second share is what proves the sender held skS.'
      : 'Encap: a fresh ephemeral key, one DH share with pkR. Anyone who knows pkR can run this — Base mode proves nothing about the sender.';

    const kemInt = kemInternals;
    kemInt.textContent = '';
    if (kem.internals.skE) kemInt.append(hexValue('skE (ephemeral private — erased after use in real deployments)', kem.internals.skE));
    kemInt.append(hexValue('pkE = enc (travels in the clear)', kem.internals.pkE));
    for (const seg of kem.internals.dhSegments) kemInt.append(hexValue(seg.label, seg.value));
    kemInt.append(
      hexValue('kem_context = enc ‖ pkRm' + (authed ? ' ‖ pkSm' : ''), kem.internals.kemContext),
      hexValue('eae_prk = LabeledExtract("", "eae_prk", dh)', kem.internals.eaePrk),
      hexValue('shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, 32)', kem.sharedSecret),
    );

    const kdfInt = kdfInternals;
    kdfInt.textContent = '';
    kdfInt.append(
      hexValue('mode byte', sch.modeByte),
      hexValue('psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)', sch.pskIdHash),
      hexValue('info_hash = LabeledExtract("", "info_hash", info)', sch.infoHash),
      hexValue('key_schedule_context = mode ‖ psk_id_hash ‖ info_hash', sch.keyScheduleContext),
      hexValue(`secret = LabeledExtract(shared_secret, "secret", ${pskUsed ? 'psk' : '"" — no psk in this mode'})`, sch.secret),
      hexValue('key = LabeledExpand(secret, "key", key_schedule_context)', sch.key),
      hexValue('base_nonce = LabeledExpand(secret, "base_nonce", …)', sch.baseNonce),
      hexValue('exporter_secret = LabeledExpand(secret, "exp", …)', sch.exporterSecret),
    );

    aeadSub.textContent = `${AEAD_NAMES[store.aeadId]} · RFC 9180 §5.2`;
    const aeadInt = aeadInternals;
    aeadInt.textContent = '';
    const nextNonce = setup.context.computeNonce();
    aeadInt.append(
      hexValue(`key (${sch.key.length} bytes — Nk of ${AEAD_NAMES[store.aeadId]})`, sch.key),
      hexValue(`nonce for next Seal = base_nonce XOR seq(${setup.context.seq})`, nextNonce),
      hexValue('AAD (authenticated, sent in clear)', new TextEncoder().encode(store.aad)),
    );

    const outKv = outputKv;
    outKv.textContent = '';
    kv(outKv, 'enc (KEM ciphertext, 32 B)', shortHex(setup.enc, 12));
    const last = store.transcript[store.transcript.length - 1];
    if (last) {
      kv(outKv, `ct #${last.seq} (${last.ct.length} B)`, shortHex(last.ct, 12));
    } else {
      outKv.append(el('dt', { text: 'ct' }), el('dd', { text: 'press “Seal the message”' }));
    }
    outputNote.textContent =
      'Everything a network observer sees: enc, ct, and the AAD. The plaintext length is visible from the ct length — HPKE does not hide it (§9.7.6).';

    arrowPkr.value.textContent = shortHex(store.recipientKeys.pk, 6);
    arrowSs.value.textContent = shortHex(kem.sharedSecret, 6);
    arrowKeys.value.textContent = `${shortHex(sch.key, 4)} · ${shortHex(sch.baseNonce, 4)} · ${shortHex(sch.exporterSecret, 4)}`;
    arrowCt.value.textContent = last ? shortHex(concatBytes(setup.enc, last.ct), 6) : shortHex(setup.enc, 6);
  };

  store.subscribe(refresh);
  refresh();
  return root;
}
