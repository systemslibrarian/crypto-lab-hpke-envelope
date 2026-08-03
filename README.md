# HPKE Envelope — crypto-lab

[![GitHub Pages](https://img.shields.io/badge/demo-live-brightgreen)](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/)

Real HPKE (RFC 9180) with every stage exposed and clickable — a KEM, a KDF, and an AEAD composed into one scheme, each stage linking out to the lab that teaches it alone.

## What It Is

**HPKE — Hybrid Public Key Encryption (RFC 9180) — is not a primitive.** It is three primitives plus a key schedule that binds them to a context: **DHKEM(X25519, HKDF-SHA256)** produces a fresh shared secret from the recipient's public key, **HKDF-SHA256** schedules that secret into AEAD keys bound to the mode byte, `psk_id`, and `info` string, and **AES-128-GCM or ChaCha20-Poly1305** seals the message. Change the info string, the AAD, or the mode, and the same three primitives produce a different key — which is the point, and also where composition breaks. All four modes (Base / PSK / Auth / AuthPSK) are implemented, with the §5.1 KeySchedule hand-rolled so every intermediate is visible.

The X25519 and HKDF operations come from the audited `@noble/curves` and `@noble/hashes` libraries; AES-128-GCM runs on the browser's WebCrypto and ChaCha20-Poly1305 on `@noble/ciphers` (WebCrypto has no ChaCha). Everything HPKE adds *around* those primitives — DeriveKeyPair, Encap/Decap/AuthEncap/AuthDecap, the labeled KDF framing, the KeySchedule, the `base_nonce XOR seq` context — is implemented in this repo and verified against the RFC 9180 Appendix A test vectors.

**Not production crypto.** This is a teaching demo: no side-channel hardening claims, no key management, and no protocol on top. All key material is generated per session and lives only in this tab's memory.

## Exhibits

1. **The pipeline** — recipient `pkR` → [KEM: Encaps] → `shared_secret` → [KDF: KeySchedule] → `key`+`base_nonce`+`exporter_secret` → [AEAD: Seal] → `ct`, drawn as three linked stages. Every stage is a real computation; expanding a stage shows every intermediate byte it computed, and each stage links out to the sibling lab that teaches that primitive alone.
2. **Four modes, one key schedule** — switch Base / PSK / Auth / AuthPSK and watch the `key_schedule_context` change byte-for-byte (highlighted), with the exact §9.1 statement of what each mode proves and its exact limit.
3. **The nonce is a counter** — a per-Seal table of `nonce = base_nonce XOR I2OSP(seq, 12)`, the changed bytes highlighted.
4. **Break the binding yourself** — sender and receiver each hold their own `info`, AAD, and mode. Edit one side and deliver: the real AEAD rejects. The panel renders **two independent indicators** — the cryptographic result and the security verdict — because "AEAD: rejected ✗" beside "Verdict: binding held ✓" is the lesson. A replay button delivers the same valid ciphertext to a fresh context: "AEAD: valid ✓" beside "Verdict: ALARM ⚠" (RFC 9180 §9.7.3).
5. **The spec's own non-goals** — the six §9.7 items (ordering/loss, downgrade, replay, forward secrecy, bad ephemeral randomness, plaintext length), each stated per the RFC and linked to the lab where it becomes the headline.
6. **Post-quantum HPKE (named, not built)** — ML-KEM-768 + X25519 as an HPKE KEM (draft-ietf-hpke-pq, shipped in Go's `crypto/hpke`): the composition absorbed PQ by swapping one stage.

## When to Use It

- Use HPKE when you need to encrypt a message (or stream) to a public key with a modern, analyzed construction — it is the envelope inside TLS Encrypted Client Hello, Oblivious HTTP, and MLS.
- Use PSK/Auth/AuthPSK modes when you need sender authentication — and read §9.1 for exactly what each proves.
- **Do NOT use** HPKE Base mode where forward secrecy against recipient-key compromise matters (it has none, in any mode — §9.7.4), where replay or downgrade must be prevented (it doesn't — §9.7.2/§9.7.3), or with a low-entropy PSK (§9.5). And do not use this repo's implementation for anything but learning.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hpke-envelope](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/)**

Seal real messages under any mode and AEAD, expand every stage's intermediates, watch the key schedule change byte-for-byte as you flip modes, and break the context binding against the real verifier.

## What Can Go Wrong

- **Context mismatch** — any disagreement in `info`, AAD, or mode derives an unrelated key; the AEAD rejects. That rejection is the design working (try it in exhibit 4).
- **Key-compromise impersonation (§9.1.1)** — the RFC's DHKEM variants are KCI-vulnerable: with the recipient's `skR`, an attacker can forge messages that Auth mode accepts as the sender's; in AuthPSK it takes the PSK and `skR` together. Named here; not built (the RFC's suggested mitigation is a signature over `(enc, ct)`).
- **Replay / reordering / loss** — outside one context's in-order sequence, HPKE provides no replay protection, and a lost message kills the context (§9.7.1, §9.7.3).
- **Bad ephemeral randomness (§9.7.5)** — degraded encapsulation randomness can cost Base mode its confidentiality entirely and can reuse key-nonce pairs, under which these AEADs fail.
- **Sequence overflow** — `seq` is bounded by the 12-byte nonce space; this implementation throws `MessageLimitError` rather than wrapping.

## Real-World Usage

TLS Encrypted Client Hello (draft-ietf-tls-esni), Oblivious HTTP (RFC 9458) and Oblivious DoH, MLS (RFC 9420) welcome messages, Apple iCloud Private Relay / key recovery, and Go 1.26's `crypto/hpke`. Post-quantum: draft-ietf-hpke-pq registers ML-KEM and hybrid X25519+ML-KEM-768 KEM code points.

## How to Run Locally

```bash
npm install
npm run dev        # Vite dev server
npm test           # 227 Vitest tests incl. RFC 9180 Appendix A KATs
npm run build      # typecheck + production build
npm run test:a11y  # Playwright: functional claims spec + axe-core WCAG 2.1 A/AA gate
```

## Related Demos

- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — the KEM stage as its own lab (ML-KEM).
- [crypto-lab-curve-lens](https://systemslibrarian.github.io/crypto-lab-curve-lens/) — the X25519 curve math this lab consumes.
- [crypto-lab-kdf-chain](https://systemslibrarian.github.io/crypto-lab-kdf-chain/) — HKDF compared with the other KDFs.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) / [crypto-lab-aegis-gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/) — AEAD internals.
- [crypto-lab-nonce-collision](https://systemslibrarian.github.io/crypto-lab-nonce-collision/) — what happens when the nonce counter fails.
- [crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — X25519 + ML-KEM-768 hybrid key exchange.
- [crypto-lab-blind-hello](https://systemslibrarian.github.io/crypto-lab-blind-hello/) — ECH, an HPKE envelope around the SNI.
- [crypto-lab-blind-relay](https://systemslibrarian.github.io/crypto-lab-blind-relay/) — Oblivious HTTP, HPKE per request.
- [crypto-lab-entropy-collapse](https://systemslibrarian.github.io/crypto-lab-entropy-collapse/) — bad randomness, §9.7.5 made visible.

## Build & Verify

- **227 Vitest tests, all passing**, of which 173 are known-answer tests from the official RFC 9180 Appendix A vectors (`src/hpke/vectors/rfc9180.json`, trimmed from the CFRG `test-vectors.json`): A.1 and A.2 suites × all four modes — DeriveKeyPair, Encap/Decap, every KeySchedule intermediate, Seal/Open at `seq ∈ {0, 1, 2, 255, 256}`, and secret export.
- The remaining tests cover fresh-key round-trips (all modes × both AEADs), the context-binding matrix (info/AAD/mode/PSK/pkS mismatches all rejected by the real AEAD; identical two-sided changes accepted; replay to a fresh context accepted — as the spec says), and fail-closed edge cases (PSK input validation, §9.5 short-PSK guard, all-zero DH rejection, malformed lengths, nonce arithmetic).
- **22 Playwright tests drive the built page in a real browser** (`e2e/claims.spec.ts`) and assert what it claims: the seal status' length arithmetic sums (ciphertext = UTF-8 plaintext bytes + 16-byte tag, checked on a multi-byte message too), every nonce table row equals `base_nonce XOR I2OSP(seq, 12)` recomputed in the test, `key_schedule_context` equals its own three rendered segments concatenated, the Base→Auth diff moves exactly one byte and Base→PSK exactly 33, all four modes × both AEADs seal for real, and every tamper path — receiver `info`, sender AAD, a one-sided mode switch, a hand-typed edit, and the replay — reaches its failure state *and* states why. The verdict is cross-checked against the panel's own computed comparison rows, so a verdict that disagrees with the bytes fails the suite.
- **Accessibility is gated in CI**: the same `npm run test:a11y` run scans the production build with axe-core for WCAG 2.1 A/AA in both themes — after driving the live demo so the dynamic result regions (including the alarm state) are scanned — and the Pages deploy runs only if the whole browser gate passes.

---

*One of 170+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
