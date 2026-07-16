/** Small DOM helpers — no framework, no innerHTML for dynamic values. */
import { bytesToHex } from '../hpke/bytes';

type Child = Node | string | null | undefined;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.append(c);
  }
  return node;
}

export function extLink(href: string, label: string): HTMLAnchorElement {
  return el('a', { href, target: '_blank', rel: 'noopener', text: label });
}

/** Short hex preview: first n bytes + ellipsis, full value available on expand. */
export function shortHex(bytes: Uint8Array, n = 8): string {
  const hex = bytesToHex(bytes);
  return bytes.length <= n ? hex : `${hex.slice(0, n * 2)}…`;
}

/** A full-width wrapping hex value with an accessible name. */
export function hexValue(label: string, bytes: Uint8Array): HTMLElement {
  const wrap = el('div', { class: 'hexrow' });
  wrap.append(
    el('span', { class: 'hexrow-label', text: label }),
    el('code', { class: 'hexblock', 'aria-label': `${label}: ${bytes.length} bytes`, text: bytesToHex(bytes) || '(empty)' }),
    el('span', { class: 'hexrow-len', text: `${bytes.length} B` }),
  );
  return wrap;
}

export type ChipTone = 'neutral' | 'ok' | 'alarm';

/**
 * VISUAL SEMANTICS: tone tracks SYSTEM INTEGRITY, never the raw crypto
 * return value. A rejected tag caused by a learner's tampering is tone 'ok'
 * (the binding held); an accepted replay is tone 'alarm'. Icons + text always
 * accompany color (WCAG 1.4.1).
 */
export function setChip(node: HTMLElement, tone: ChipTone, icon: string, text: string): void {
  node.className = `chip chip-${tone}`;
  node.textContent = '';
  node.append(el('span', { class: 'chip-icon', 'aria-hidden': 'true', text: icon }), ' ', text);
}
