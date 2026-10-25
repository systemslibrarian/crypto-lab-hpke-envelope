# HPKE Envelope — crypto-lab

[![GitHub Pages](https://img.shields.io/badge/demo-live-brightgreen)](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/)

Real HPKE (RFC 9180) with every stage exposed and clickable — plus an executable recipient-key KCI attack and a bounded identity-bound Sign-then-Encrypt comparison.

## What It Is

**HPKE — Hybrid Public Key Encryption (RFC 9180) — is not a primitive.** It is three primitives plus a key schedule that binds them to a context: **DHKEM(X25519, HKDF-SHA256)** produces a fresh shared secret from the recipient's public key, **HKDF-SHA256** schedules that secret into AEAD keys bound to the mode byte, `psk_id`, and `info` string, and **AES-128-GCM or ChaCha20-Poly1305** seals the message. Changing `info` or the mode changes the key-schedule binding and derived key. AAD is authenticated by the AEAD: changing it changes the tag and acceptance, not the derived key. All four modes (Base / PSK / Auth / AuthPSK) are implemented, with the §5.1 KeySchedule hand-rolled so every intermediate is visible.

The X25519 and HKDF operations come from the audited `@noble/curves` and `@noble/hashes` libraries; AES-128-GCM runs on the browser's WebCrypto and ChaCha20-Poly1305 on `@noble/ciphers` (WebCrypto has no ChaCha). Everything HPKE adds *around* those primitives — DeriveKeyPair, Encap/Decap/AuthEncap/AuthDecap, the labeled KDF framing, the KeySchedule, the `base_nonce XOR seq` context — is implemented in this repo and verified against the RFC 9180 Appendix A test vectors.

**Not production crypto.** This is a teaching demo: no side-channel hardening claims, no key management, and no protocol on top. All key material is generated per session and lives only in this tab's memory.

## Exhibits

1. **The pipeline** — recipient `pkR` → [KEM: Encaps] → `shared_secret` → [KDF: KeySchedule] → `key`+`base_nonce`+`exporter_secret` → [AEAD: Seal] → `ct`, drawn as three linked stages. Every stage is a real computation; expanding a stage shows every intermediate byte it computed, and each stage links out to the sibling lab that teaches that primitive alone.
2. **Four modes, one key schedule** — switch Base / PSK / Auth / AuthPSK and watch the `key_schedule_context` change byte-for-byte (highlighted), with the exact §9.1 statement of what each mode proves and its exact limit.
3. **The nonce is a counter** — a per-Seal table of `nonce = base_nonce XOR I2OSP(seq, 12)`, the changed bytes highlighted.
4. **Break the binding yourself** — sender and receiver each hold their own `info`, AAD, and mode. Edit one side and deliver: the real AEAD rejects. The panel renders **two independent indicators** — the cryptographic result and the security verdict — because "AEAD: rejected ✗" beside "Verdict: binding held ✓" is the lesson. A replay button delivers the same valid ciphertext to a fresh context: "AEAD: valid ✓" beside "Verdict: ALARM ⚠" (RFC 9180 §9.7.3).
5. **Sender evidence under compromise** — execute RFC 9180 Auth's §9.1.1 recipient-key KCI forgery, then compare it with an An–Dodis–Rabin-style multi-user Sign-then-Encrypt teaching profile built from Base HPKE and strict Ed25519. The run binds Sara, Ravi, the application context and the message; rejects outsider tampering, changed recipient-authored content and surreptitious forwarding; demonstrates sender-key compromise and replay; and exports public signature evidence that must be checked against Sara's separately pinned key.
6. **The spec's own non-goals** — the six §9.7 items (ordering/loss, downgrade, replay, forward secrecy, bad ephemeral randomness, plaintext length), each stated per the RFC and linked to the lab where it becomes the headline.
7. **Post-quantum HPKE (named, not built)** — ML-KEM-768 + X25519 as an HPKE KEM (draft-ietf-hpke-pq, shipped in Go's `crypto/hpke`): the composition absorbed PQ by swapping one stage.

## When to Use It

- Use HPKE when you need to encrypt a message (or stream) to a public key with a modern, analyzed construction — it is the envelope inside TLS Encrypted Client Hello, Oblivious HTTP, and MLS.
- Use PSK/Auth/AuthPSK modes when you need sender authentication — and read §9.1 for exactly what each proves.
- Use the signcryption comparison to study insider-security and transferable-signature boundaries, not as a wire format to deploy.
- **Do NOT use** HPKE Base mode where forward secrecy against recipient-key compromise matters (it has none, in any mode — §9.7.4), where replay or downgrade must be prevented (it doesn't — §9.7.2/§9.7.3), or with a low-entropy PSK (§9.5). And do not use this repo's implementation for anything but learning.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hpke-envelope](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/)**

Seal real messages under any mode and AEAD, expand every stage's intermediates, watch the key schedule change byte-for-byte as you flip modes, and break the context binding against the real verifier.

## What Can Go Wrong

- **Context mismatch** — disagreement in `info` or mode changes the derived key; disagreement in AAD leaves the key unchanged but fails tag verification. In either case the AEAD rejects. That rejection is the design working (try it in exhibit 4).
- **Key-compromise impersonation (§9.1.1)** — the RFC's DHKEM variants are KCI-vulnerable: with the recipient's `skR`, an attacker can forge messages that Auth mode accepts as the sender's; in AuthPSK it takes the PSK and `skR` together. Exhibit 5 computes the Auth forgery using `skR` and public `pkS`, without `skS`.
- **Replay / reordering / loss** — outside one context's in-order sequence, HPKE provides no replay protection, and a lost message kills the context (§9.7.1, §9.7.3).
- **Bad ephemeral randomness (§9.7.5)** — degraded encapsulation randomness can cost Base mode its confidentiality entirely and can reuse key-nonce pairs, under which these AEADs fail.
- **Sequence overflow** — `seq` is bounded by the 12-byte nonce space; this implementation throws `MessageLimitError` rather than wrapping.

## Context API concurrency

`HpkeContext.seal()` and `open()` serialize operations on each context in invocation order. Each operation reads the current sequence only when it starts, then advances it after successful AEAD processing (RFC 9180 §5.2). A failed operation leaves the sequence unchanged and does not prevent later queued operations from running. Concurrent opens must be submitted in the sender's message order; queuing does not reorder ciphertexts or add replay protection. Do not modify `seq`, key material, or input buffers while operations are pending; the public sequence field remains available for the teaching panels and vector tests.

## Signcryption profile and evidence boundary

Exhibit 5 instantiates the generic multi-user Sign-then-Encrypt construction analyzed by [An, Dodis and Rabin](https://eprint.iacr.org/2002/046) with RFC 9180 Base HPKE and [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) Ed25519. It uses independent X25519 and Ed25519 key pairs. A versioned, length-framed, domain-separated transcript signs the sender identity, intended recipient identity, application context and message; the HPKE `info` and AAD separately bind the same outer identities and context. Identities resolve to pinned keys outside the packet: a disclosed key is never trusted merely because the evidence carries it. Version 1 fixes DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM and strict Ed25519 rather than negotiating a suite.

This is a bounded teaching profile, not a standardized signcryption wire format and not a claim that the paper's proof transfers automatically to this implementation. Recipient-key compromise exposes ciphertexts to that recipient but does not create a new valid sender signature while the Ed25519 key remains safe. Sender signing-key compromise permits new signed forgeries but, by itself, does not open recorded Base-HPKE ciphertexts to an uncompromised recipient. Compromise of both loses both properties. The implementation quarantines decrypted bytes until the strict signature and all identity/context bindings pass.

Transferable evidence is deliberately narrow. A third party can verify that the separately pinned Ed25519 key signed the exact disclosed sender, recipient, context and message. That does not prove who created the HPKE ciphertext, whether it was transmitted or received, when it was signed, human intent, or legal non-repudiation. A recipient can re-encrypt an unchanged valid signed payload, and this profile has no message identifier or replay cache: delivering the same packet twice succeeds cryptographically and requires application replay state.

Standards status checked 2026-10-25: RFC 9180 is the implemented 2022 Informational baseline. The active [HPKE working-group Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/) remains work in progress and currently omits Auth modes; it is not silently treated here as an approved replacement standard.

## Real-World Usage

TLS Encrypted Client Hello ([RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html), Standards Track, March 2026), with DNS Service Binding bootstrap in [RFC 9848](https://www.rfc-editor.org/info/rfc9848/), Oblivious HTTP (RFC 9458) and Oblivious DoH, MLS (RFC 9420) welcome messages, Apple iCloud Private Relay / key recovery, and Go 1.26's `crypto/hpke`. This lab implements RFC 9180 HPKE, not the full ECH or DNS bootstrap protocol; see [Blind Hello](https://systemslibrarian.github.io/crypto-lab-blind-hello/) for the ECH lesson. Post-quantum: draft-ietf-hpke-pq registers ML-KEM and hybrid X25519+ML-KEM-768 KEM code points.

## How to Run Locally

```bash
npm install
npm run dev        # Vite dev server
npm test           # 258 Vitest tests incl. RFC 9180 Appendix A KATs
npm run test:mutations # passing baseline + 19 S01 security mutations caught
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

- **258 Vitest tests, all passing**, of which 173 are known-answer tests from the official RFC 9180 Appendix A vectors (`src/hpke/vectors/rfc9180.json`, trimmed from the CFRG `test-vectors.json`): A.1 and A.2 suites × all four modes — DeriveKeyPair, Encap/Decap, every KeySchedule intermediate, Seal/Open at `seq ∈ {0, 1, 2, 255, 256}`, and secret export.
- The remaining tests cover fresh-key round-trips (all modes × both AEADs), the context-binding matrix, concurrent Seal/Open ordering and failure recovery, fail-closed HPKE edge cases, and 19 S01 construction tests. Those S01 tests include RFC 8032 Test 1, strict rejection of an identity-point signature accepted by ZIP-215, canonical framing, unsupported-version rejection, each independent multi-user binding, recipient/sender compromise, forwarding, pinned-key evidence, application-plaintext quarantine and an executable RFC 9180 KCI forge.
- **27 Playwright tests drive the built page in a real browser** (`e2e/claims.spec.ts` plus the accessibility drive) and assert what it claims. In addition to the existing pipeline, mode, nonce, tamper and replay checks, the S01 tests execute all compromise cases, independently decode the displayed signed tuple and verify its Ed25519 signature with Node/OpenSSL rather than the browser's Noble verifier, and require input changes to retire every prior result and trace.
- **19 source mutations** run only after an unmodified focused-test baseline passes. They remove individual sender/recipient/context bindings (including the receiver's independently expected context), weaken strict Ed25519 and canonical framing, trust an evidence-supplied key, release rejected plaintext/evidence, change the KCI mode and weaken an input bound; every mutation must be caught and the exact source is restored after each case.
- **Accessibility is gated in CI**: the same `npm run test:a11y` run scans the production build with axe-core for WCAG 2.1 A/AA in the shipped dark theme at desktop and 380px widths — after driving the live demo so the dynamic result regions (including compromise alarms) are scanned — and the Pages deploy runs only if the whole browser gate passes.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
