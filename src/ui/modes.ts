/**
 * Mode switcher panel: what each mode adds to the key schedule input, shown
 * byte-for-byte, and exactly what each mode proves (RFC 9180 §9.1 — the
 * claims below track the spec's wording; do not "improve" them).
 */
import { bytesToHex } from '../hpke/bytes';
import { type Mode, MODE_AUTH, MODE_AUTH_PSK, MODE_BASE, MODE_NAMES, MODE_PSK, modeUsesAuth } from '../hpke/consts';
import { el } from './dom';
import type { LabStore } from './state';

interface ModeFacts {
  adds: string;
  proves: string;
  caveat: string;
}

const MODE_FACTS: Record<Mode, ModeFacts> = {
  [MODE_BASE]: {
    adds: 'Nothing extra: mode byte 0x00, psk_id_hash of the empty string, one DH share in the KEM.',
    proves:
      'Secrecy only. No sender authentication — anyone who knows pkR can produce a ciphertext the recipient will accept.',
    caveat:
      'Secrecy is expected to hold only if the recipient private key skR is never compromised (§9.1) — there is no forward secrecy with respect to recipient compromise.',
  },
  [MODE_PSK]: {
    adds:
      'The mode byte becomes 0x01, psk_id_hash now hashes your psk_id, and the PSK itself enters as the second input to secret = LabeledExtract(shared_secret, "secret", psk).',
    proves:
      'Sender authentication via the pre-shared key: proof that the sender holds the PSK (§9.1).',
    caveat:
      'Secrecy is expected to hold if skR and the PSK are not BOTH compromised — the PSK is a second lock, not a second identity.',
  },
  [MODE_AUTH]: {
    adds:
      'The mode byte becomes 0x02 and the KEM runs a SECOND Diffie-Hellman, DH(skS, pkR), concatenated with the first — the key schedule itself is unchanged except for the mode byte.',
    proves:
      'Sender authentication via the sender’s static key: generally expected to hold if skS is not compromised at the time of message reception (§9.1).',
    caveat:
      'Key-compromise impersonation (§9.1.1): if the RECIPIENT’s skR is compromised, sender authentication cannot be expected to hold — an attacker with skR can forge messages “from” the sender. This lab names that limit; it does not build the attack.',
  },
  [MODE_AUTH_PSK]: {
    adds: 'Both additions at once: mode byte 0x03, the PSK in secret, psk_id in the context, and the second DH in the KEM.',
    proves:
      'Sender authentication is expected to hold if skS and the PSK are not both compromised at the time of message reception (§9.1).',
    caveat:
      'KCI needs both the PSK and skR compromised (§9.1.1). RFC 9180 also notes a PSK preserves security if a non-quantum-resistant KEM is later broken — see the post-quantum panel below.',
  },
};

export function renderModes(store: LabStore): HTMLElement {
  const root = el('section', { class: 'panel', 'aria-labelledby': 'modes-h' });
  root.append(
    el('h2', { id: 'modes-h', text: 'Four modes, one key schedule' }),
    el('p', { class: 'panel-lede' },
      'Base, PSK, Auth, and AuthPSK are not four schemes — they are four values of one mode byte plus two optional ingredients. ',
      'Switch modes in the pipeline above and watch which bytes of the key schedule input change below. ',
      el('strong', {}, 'Every changed input byte yields an unrelated key'), ' — that is the binding.'),
  );

  const byteView = el('div', { class: 'byteview', role: 'group', 'aria-label': 'key_schedule_context bytes' });
  const diffSummary = el('p', { class: 'note', role: 'status', 'aria-live': 'polite' });
  const factsBox = el('div', { class: 'mode-facts' });
  root.append(byteView, diffSummary, factsBox);

  const segment = (label: string, hex: string, changedIdx: Set<number>, offset: number) => {
    const seg = el('div', { class: 'byteseg' });
    seg.append(el('span', { class: 'byteseg-label', text: label }));
    const bytesWrap = el('code', { class: 'byteseg-bytes' });
    for (let i = 0; i < hex.length; i += 2) {
      const byteIdx = offset + i / 2;
      const byte = hex.slice(i, i + 2);
      bytesWrap.append(
        changedIdx.has(byteIdx)
          ? el('mark', { class: 'byte byte-changed', title: 'changed vs previous mode', text: byte })
          : el('span', { class: 'byte', text: byte }),
      );
    }
    seg.append(bytesWrap);
    return seg;
  };

  const refresh = () => {
    const sch = store.setup.schedule;
    const cur = sch.keyScheduleContext;
    const prev = store.prevKsc;
    const changed = new Set<number>();
    if (prev && prev.length === cur.length) {
      for (let i = 0; i < cur.length; i++) if (cur[i] !== prev[i]) changed.add(i);
    }

    byteView.textContent = '';
    byteView.append(
      el('p', { class: 'byteview-title' },
        el('code', {}, 'key_schedule_context'), ` for mode ${MODE_NAMES[store.mode]} — `,
        el('code', {}, 'mode ‖ psk_id_hash ‖ info_hash'), ` (${cur.length} bytes)`),
      segment('mode (1 B)', bytesToHex(sch.modeByte), changed, 0),
      segment('psk_id_hash (32 B)', bytesToHex(sch.pskIdHash), changed, 1),
      segment('info_hash (32 B)', bytesToHex(sch.infoHash), changed, 33),
    );

    if (prev && store.prevMode !== null && store.prevMode !== store.mode) {
      const parts: string[] = [];
      if (changed.has(0)) parts.push('the mode byte');
      if ([...changed].some((i) => i >= 1 && i < 33)) parts.push('psk_id_hash');
      if ([...changed].some((i) => i >= 33)) parts.push('info_hash');
      diffSummary.textContent = changed.size === 0
        ? 'No schedule-context bytes changed.'
        : `${changed.size} byte${changed.size === 1 ? '' : 's'} changed versus mode ${MODE_NAMES[store.prevMode]} (highlighted): ${parts.join(' and ')}. ` +
          (modeUsesAuth(store.mode) !== modeUsesAuth(store.prevMode)
            ? 'The Auth-mode second DH changed shared_secret upstream as well, so every derived key below is new. '
            : 'shared_secret is unchanged — yet key, base_nonce, and exporter_secret are all different because the context bytes feed every LabeledExpand. ');
    } else {
      diffSummary.textContent = 'Switch modes in the pipeline above to see the changed bytes highlighted here.';
    }

    const facts = MODE_FACTS[store.mode];
    factsBox.textContent = '';
    factsBox.append(
      el('h3', { text: `Mode ${MODE_NAMES[store.mode]}` }),
      el('p', {}, el('strong', {}, 'What it adds: '), facts.adds),
      el('p', {}, el('strong', {}, 'What it proves: '), facts.proves),
      el('p', {}, el('strong', {}, 'The exact limit: '), facts.caveat),
    );
  };

  store.subscribe(refresh);
  refresh();
  return root;
}
