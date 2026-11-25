/**
 * Sequence / nonce panel: base_nonce XOR seq, one row per real Seal.
 * The nonce is never random and never transmitted — both sides count.
 */
import { bytesToHex } from '../hpke/bytes';
import { el, extLink, shortHex } from './dom';
import { LABS } from './links';
import type { LabStore } from './state';

export function renderNoncePanel(store: LabStore): HTMLElement {
  const root = el('section', { class: 'panel', 'aria-labelledby': 'nonce-h' });
  root.append(
    el('h2', { id: 'nonce-h', text: 'The nonce is a counter in disguise' }),
    el('p', { class: 'panel-lede' },
      'Each Seal uses ', el('code', {}, 'nonce = base_nonce XOR I2OSP(seq, 12)'),
      ' and then increments seq. Seal the message repeatedly in the pipeline above and watch only the low bytes move. ',
      'If a nonce ever repeated under the same key, both AEADs here would fail catastrophically — ',
      extLink(LABS.nonceCollision, 'nonce-collision'), ' is the lab where you cause exactly that.'),
  );

  // Horizontally scrollable on narrow screens → must be keyboard-reachable.
  const tableWrap = el('div', { class: 'tablewrap', tabindex: '0', role: 'region', 'aria-label': 'Nonce derivation table' });
  const status = el('p', { class: 'note', role: 'status', 'aria-live': 'polite' });
  root.append(tableWrap, status);

  const refresh = () => {
    tableWrap.textContent = '';
    const baseNonce = store.setup.schedule.baseNonce;
    const table = el('table', { class: 'nonce-table' });
    table.append(
      el('caption', { class: 'sr-only', text: 'Nonce derivation per sealed message' }),
      el('thead', {},
        el('tr', {},
          el('th', { scope: 'col', text: 'seq' }),
          el('th', { scope: 'col', text: 'I2OSP(seq, 12)' }),
          el('th', { scope: 'col', text: 'XOR base_nonce →  nonce' }),
          el('th', { scope: 'col', text: 'ct' }),
        )),
    );
    const tbody = el('tbody');

    const nonceCell = (nonce: Uint8Array) => {
      const code = el('code', { class: 'inline-hex' });
      const base = bytesToHex(baseNonce);
      const hex = bytesToHex(nonce);
      for (let i = 0; i < hex.length; i += 2) {
        const same = hex.slice(i, i + 2) === base.slice(i, i + 2);
        code.append(same
          ? el('span', { text: hex.slice(i, i + 2) })
          : el('mark', { class: 'byte-changed', title: 'differs from base_nonce', text: hex.slice(i, i + 2) }));
      }
      return code;
    };

    tbody.append(el('tr', { class: 'nonce-base-row' },
      el('th', { scope: 'row', text: 'base' }),
      el('td', {}, el('code', { class: 'inline-hex', text: '—' })),
      el('td', {}, el('code', { class: 'inline-hex', text: bytesToHex(baseNonce) })),
      el('td', { text: '(base_nonce from the key schedule)' }),
    ));

    for (const entry of store.transcript) {
      tbody.append(el('tr', {},
        el('th', { scope: 'row', text: String(entry.seq) }),
        el('td', {}, el('code', { class: 'inline-hex', text: bytesToHex(entry.seqBytes) })),
        el('td', {}, nonceCell(entry.nonce)),
        el('td', {}, el('code', { class: 'inline-hex', text: shortHex(entry.ct, 8) })),
      ));
    }
    table.append(tbody);
    tableWrap.append(table);

    const nextSeq = store.setup.context.seq;
    if (store.transcript.length) {
      status.textContent = `${store.transcript.length} message${store.transcript.length === 1 ? '' : 's'} sealed; next Seal will use seq ${nextSeq}. Rows show seals for the current plaintext and AAD.`;
    } else {
      status.textContent = nextSeq === 0n
        ? 'No messages sealed in this context yet.'
        : `No seals shown for the current plaintext and AAD. This context continues at seq ${nextSeq}.`;
    }
  };

  store.subscribe(refresh);
  refresh();
  return root;
}
