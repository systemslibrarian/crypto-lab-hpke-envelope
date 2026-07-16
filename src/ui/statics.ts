/**
 * Static panels: plain-language intro, the RFC 9180 §9.7 non-goals (the
 * spec's own words, not ours), the post-quantum panel (named, not built),
 * and the scope strip. Consequence claims here track the RFC exactly —
 * precision drift is a build failure for this lab.
 */
import { el, extLink } from './dom';
import { LABS } from './links';

export function renderIntro(): HTMLElement {
  const root = el('section', { class: 'panel panel-intro', 'aria-labelledby': 'intro-h' });
  root.append(
    el('h2', { id: 'intro-h', text: 'What is this?' }),
    el('p', {},
      'HPKE — Hybrid Public Key Encryption — is how modern protocols encrypt a message to someone’s public key. ',
      'It is not a new primitive: it is three existing ones (a key-encapsulation mechanism, a key-derivation function, and an authenticated cipher) ',
      'snapped together by a small key schedule. That schedule binds the derived keys to a context — which mode you ran, ',
      'which application string you passed — so two parties get the same keys only if they agree on everything.'),
    el('p', {},
      'Why it matters: the security of the composition lives in that binding, not in any one primitive. ',
      'TLS Encrypted Client Hello, Oblivious HTTP, Apple iCloud key recovery, and MLS all carry HPKE envelopes. ',
      'And because the schedule only ever consumes a shared secret, the KEM stage could be swapped for a post-quantum one without touching the rest — which is exactly what happened.'),
    el('p', { class: 'honesty' },
      el('strong', {}, 'Honest scope: '),
      'this is a teaching demo, not production crypto. The X25519, HKDF-SHA256, AES-128-GCM, and ChaCha20-Poly1305 underneath are real ',
      '(audited @noble libraries and the browser’s WebCrypto), and the HPKE key schedule is implemented here by hand and checked against ',
      'the RFC 9180 Appendix A test vectors. What it does NOT prove: side-channel resistance, secure key storage, or the security of any ',
      'protocol you might build on top. All key material is generated per session, in this tab’s memory only.'),
    el('details', { class: 'expert' },
      el('summary', { text: 'For the cryptographer' }),
      el('p', {},
        'Suite: DHKEM(X25519, HKDF-SHA256) (kem_id 0x0020), HKDF-SHA256 (kdf_id 0x0001), AES-128-GCM (0x0001) / ChaCha20-Poly1305 (0x0003); ',
        'all four modes, KeySchedule per RFC 9180 §5.1, secret export per §5.3. HPKE Base is IND-CCA2 under IND-CCA2 KEM + AEAD (Cramer–Shoup lineage; see §9.1.2); ',
        'the labeled HKDF calls provide the domain separation (§9.6). The mode byte, psk_id_hash, and info_hash enter key_schedule_context; ',
        'the PSK enters the Extract that produces `secret` — the panels below show all of it byte-for-byte.')),
  );
  return root;
}

interface NonGoal {
  section: string;
  title: string;
  claim: (string | Node)[];
  link: Node;
}

export function renderNonGoals(): HTMLElement {
  const root = el('section', { class: 'panel', 'aria-labelledby': 'nongoals-h' });
  root.append(
    el('h2', { id: 'nongoals-h', text: 'What HPKE deliberately does not do (RFC 9180 §9.7)' }),
    el('p', { class: 'panel-lede' },
      'These are the spec’s own stated non-goals — properties HPKE leaves to the application. ',
      'Each one is the opening move of another lab. None of them is a flaw; each becomes one the moment an application assumes HPKE handles it.'),
  );

  const goals: NonGoal[] = [
    {
      section: '§9.7.1',
      title: 'Message order and message loss',
      claim: ['Ciphertexts MUST be presented to Open() in the order they were generated — the nonce is a counter, so a skipped or reordered message simply fails to decrypt. HPKE is not tolerant of lost messages: on unrecoverable loss the application must discard the context.'],
      link: el('span', {}, 'Cause it above: the out-of-order case is in this lab’s test suite, and the sequence panel shows why.'),
    },
    {
      section: '§9.7.2',
      title: 'Downgrade prevention',
      claim: ['HPKE assumes sender and recipient agree on which algorithms to use. Depending on how those are negotiated, an intermediary may be able to force suboptimal algorithms.'],
      link: el('span', {}, 'The negotiation attack: ', extLink(LABS.downgradeWire, 'downgrade-wire'), '.'),
    },
    {
      section: '§9.7.3',
      title: 'Replay protection',
      claim: ['In-order delivery within one context gives a degree of replay protection; beyond that, “HPKE provides no other replay protection.” A ciphertext replayed to a fresh context opens perfectly — the replay button above proves it.'],
      link: el('span', {}, 'How OHTTP scopes each request to its own context: ', extLink(LABS.blindRelay, 'blind-relay'), '.'),
    },
    {
      section: '§9.7.4',
      title: 'Forward secrecy',
      claim: ['HPKE ciphertexts are not forward secret with respect to recipient compromise in ANY mode: compromise of the long-term recipient secrets allows decryption of past ciphertexts encrypted under them. They ARE forward secret with respect to sender compromise in all modes, because the sender’s side is ephemeral.'],
      link: el('span', {}, 'What forward secrecy takes — ratcheting: ', extLink(LABS.ratchetWire, 'ratchet-wire'), '.'),
    },
    {
      section: '§9.7.5',
      title: 'Bad ephemeral randomness',
      claim: ['If the encapsulation randomness is low-entropy or compromised, confidentiality degrades significantly — in Base mode it can be lost completely; in the other modes, at least forward secrecy with respect to sender compromise can be lost completely. It can also cause key-nonce pair reuse, under which these AEADs are not secure.'],
      link: el('span', {}, 'Watch an RNG die: ', extLink(LABS.entropyCollapse, 'entropy-collapse'), '.'),
    },
    {
      section: '§9.7.6',
      title: 'Hiding plaintext length',
      claim: ['AEAD ciphertexts produced by HPKE do not hide the plaintext length (the seal status above prints it). Padding is the application’s job — the RFC points at TLS Encrypted Client Hello’s padding policy as the worked example.'],
      link: el('span', {}, 'ECH, where that padding lives: ', extLink(LABS.blindHello, 'blind-hello'), '.'),
    },
  ];

  const grid = el('div', { class: 'nongoal-grid' });
  for (const g of goals) {
    grid.append(el('div', { class: 'nongoal-card' },
      el('h3', {}, el('span', { class: 'nongoal-sec', text: g.section }), ' ', g.title),
      el('p', {}, ...g.claim),
      el('p', { class: 'nongoal-link' }, g.link),
    ));
  }
  root.append(grid);
  return root;
}

export function renderPqPanel(): HTMLElement {
  const root = el('section', { class: 'panel', 'aria-labelledby': 'pq-h' });
  root.append(
    el('h2', { id: 'pq-h', text: 'Post-quantum HPKE: swap one stage (named, not built)' }),
    el('p', {},
      'The key schedule never sees the KEM — it only consumes a 32-byte ', el('code', {}, 'shared_secret'),
      '. That seam is why HPKE absorbed post-quantum cryptography by swapping a single stage: ',
      el('strong', {}, 'ML-KEM-768 + X25519 as a hybrid HPKE KEM'),
      ' (draft-ietf-hpke-pq, shipped in Go’s crypto/hpke), slotted where DHKEM(X25519) sits in the pipeline above. ',
      'The KDF and AEAD stages, the mode byte, the info binding, the nonce counter — all byte-for-byte unchanged.'),
    el('p', {},
      'One caveat carried over from §9.1.1: the Auth modes are DH-specific, so the hybrid PQ KEMs run Base and PSK modes; and RFC 9180 itself notes that a PSK preserves HPKE’s security properties if a non-quantum-resistant KEM is later broken by a quantum computer — the PSK mode you just toggled is also the harvest-now-decrypt-later hedge.'),
    el('p', { class: 'nongoal-link' },
      'This lab names that KEM and stops. See it built: ', extLink(LABS.hybridWire, 'hybrid-wire'),
      ' (X25519 + ML-KEM-768 on the wire) and ', extLink(LABS.kyberVault, 'kyber-vault'), ' (the lattice KEM itself).'),
  );
  return root;
}

export function renderScopeStrip(): HTMLElement {
  const root = el('section', { class: 'panel panel-scope', 'aria-labelledby': 'scope-h' });
  root.append(
    el('h2', { id: 'scope-h', text: 'What this lab isn’t' }),
    el('ul', { class: 'scope-list' },
      el('li', {}, 'Not a KEM lab — the X25519 math is consumed, not exposed; ', extLink(LABS.kyberVault, 'kyber-vault'), ' and ', extLink(LABS.curveLens, 'curve-lens'), ' own it.'),
      el('li', {}, 'Not a KDF lab — HKDF is one link of ', extLink(LABS.kdfChain, 'kdf-chain'), '; here you only see what HPKE feeds it.'),
      el('li', {}, 'Not an AEAD lab — GCM/Poly1305 internals live in ', extLink(LABS.aesModes, 'aes-modes'), ' and ', extLink(LABS.aegisGate, 'aegis-gate'), '.'),
      el('li', {}, 'Not an ECH or OHTTP lab — those protocols carry HPKE envelopes; ', extLink(LABS.blindHello, 'blind-hello'), ' and ', extLink(LABS.blindRelay, 'blind-relay'), ' are the separate labs.'),
      el('li', {},
        'No key-compromise-impersonation build-out. Named exactly, per RFC 9180 §9.1.1: the DHKEM variants in the RFC are vulnerable to KCI — sender authentication cannot be expected to hold in Auth mode if the recipient’s skR is compromised, nor in AuthPSK mode if the PSK and skR are both compromised. The suggested mitigation is a signature over (enc, ct).'),
    ),
  );
  return root;
}
