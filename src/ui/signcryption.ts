/**
 * S01: executable multi-user signcryption comparison.
 *
 * This panel deliberately keeps the ADR Sign-then-Encrypt construction beside
 * RFC 9180 Auth. It does not present the teaching packet as a standardized
 * wire format or transfer ADR's proof to this code.
 */
import { bytesToHex } from '../hpke/bytes';
import {
  authOpen,
  authSeal,
  createParty,
  designcrypt,
  flipSteCiphertext,
  forgeAfterRecipientCompromise,
  forgeAuthAfterRecipientCompromise,
  forwardToAnotherRecipient,
  signcrypt,
  verifyTransferEvidence,
  type DeSigncryptResult,
  type LessonParty,
} from '../signcryption/ste';
import { el, extLink, setChip, type ChipTone } from './dom';

interface ResultLine {
  id: string;
  label: string;
  expectation: string;
}

const RESULT_LINES: ResultLine[] = [
  {
    id: 's01-honest',
    label: 'Honest delivery',
    expectation: 'Both constructions accept under the intended keys and context.',
  },
  {
    id: 's01-outsider',
    label: 'Outsider changes the StE ciphertext',
    expectation: 'The HPKE tag rejects before any signed plaintext is released.',
  },
  {
    id: 's01-auth-kci',
    label: 'Recipient HPKE key compromised: Auth',
    expectation: 'RFC 9180 KCI: skR alone can make a fresh ciphertext accepted as Sara.',
  },
  {
    id: 's01-ste-recipient',
    label: 'Recipient HPKE key compromised: StE',
    expectation: 'Ravi can decrypt, but a changed message fails Sara’s pinned Ed25519 key.',
  },
  {
    id: 's01-forward',
    label: 'Recipient forwards the signed payload to Rita',
    expectation: 'The signature still verifies, but its signed recipient is Ravi, so Rita rejects.',
  },
  {
    id: 's01-sender',
    label: 'Sender signing key compromised',
    expectation: 'New StE forgeries verify; recorded ciphertexts remain hidden while skR is safe.',
  },
  {
    id: 's01-both',
    label: 'Sender signing key and recipient HPKE key compromised',
    expectation: 'The attacker can open recorded packets and create fresh accepted signed content.',
  },
  {
    id: 's01-evidence',
    label: 'Recipient discloses StE evidence',
    expectation: 'A third party verifies the exact transcript against Sara’s separately pinned key.',
  },
  {
    id: 's01-replay',
    label: 'Same StE packet delivered twice',
    expectation: 'Both opens succeed: this stateless construction supplies no replay policy.',
  },
];

function resultCard(line: ResultLine): { card: HTMLElement; chip: HTMLElement; note: HTMLElement } {
  const chip = el('p', { class: 'chip chip-neutral', id: line.id });
  const note = el('p', { class: 'note', text: line.expectation });
  setChip(chip, 'neutral', '·', 'not run');
  return {
    card: el('article', { class: 's01-result-card' },
      el('h3', { text: line.label }),
      chip,
      note,
    ),
    chip,
    note,
  };
}

function verdict(
  target: HTMLElement,
  tone: ChipTone,
  icon: string,
  text: string,
  detail: HTMLElement,
  explanation: string,
): void {
  setChip(target, tone, icon, text);
  detail.textContent = explanation;
}

function acceptedSummary(result: DeSigncryptResult): string {
  return `HPKE open ${result.hpkeOpened ? 'yes' : 'no'}; strict signature ${result.signatureValid ? 'valid' : 'invalid'}; bindings ${result.bindingsMatch ? 'match' : 'do not match'}.`;
}

function matrixRow(
  threat: string,
  confidentiality: string,
  authenticity: string,
  reason: string,
): HTMLTableRowElement {
  return el('tr', {},
    el('th', { scope: 'row', text: threat }),
    el('td', { text: confidentiality }),
    el('td', { text: authenticity }),
    el('td', { text: reason }),
  );
}

export function renderSigncryption(): HTMLElement {
  const root = el('section', { class: 'panel', 'aria-labelledby': 'signcryption-h' });
  root.append(
    el('h2', { id: 'signcryption-h', text: 'Sender evidence under key compromise: Auth versus Sign-then-Encrypt' }),
    el('p', { class: 'panel-lede' },
      'RFC 9180 Auth authenticates a sender to its recipient with a second Diffie–Hellman share, but §9.1.1 gives it a precise recipient-key-compromise limit. ',
      'Run the cases below to execute that KCI forgery and compare it with a bounded multi-user Sign-then-Encrypt (StE) teaching construction: strict Ed25519 signs ',
      el('code', {}, '(sender, recipient, application context, message)'),
      ', then Base HPKE encrypts the signed transcript.'),
    el('p', { class: 'honesty' },
      el('strong', {}, 'Scope and standards status (checked 25 October 2026): '),
      'the Auth mode here is the ', extLink('https://www.rfc-editor.org/rfc/rfc9180.html', 'RFC 9180'),
      ' Informational specification from 2022. The active HPKE successor ',
      extLink('https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/', 'working-group Internet-Draft'),
      ' is work in progress and currently omits Auth modes. The StE packet is this lab’s versioned application profile of the generic ',
      extLink('https://eprint.iacr.org/2002/046', 'An–Dodis–Rabin construction'),
      ' with ', extLink('https://www.rfc-editor.org/rfc/rfc8032.html', 'RFC 8032 Ed25519'),
      '; it is not a standardized wire format, a production protocol, or a claim that the paper’s proof transfers automatically to this code.'),
    el('p', { class: 'note' },
      'Profile boundary: version 1 fixes DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, and strict Ed25519 in domain-separated encodings; the packet cannot negotiate alternatives. ',
      'Sender and recipient names resolve to pinned keys outside the packet. This profile intentionally has no message identifier or replay cache, so a valid replay remains valid cryptography.'),
  );

  const contextInput = el('input', {
    type: 'text',
    id: 's01-context',
    value: 'registrar.example/grade-release/v1',
    maxlength: '512',
  }) as HTMLInputElement;
  const messageInput = el('input', {
    type: 'text',
    id: 's01-message',
    value: 'Course result: pass',
    maxlength: '4096',
  }) as HTMLInputElement;
  const run = el('button', {
    type: 'button',
    class: 'btn btn-primary',
    id: 's01-run',
    text: 'Run all compromise cases',
  }) as HTMLButtonElement;
  const status = el('p', {
    class: 'note',
    id: 's01-status',
    role: 'status',
    'aria-live': 'polite',
    text: 'No cases run yet. Editing either input retires the previous results.',
  });
  root.append(el('div', { class: 'controls s01-controls' },
    el('p', { class: 'ctl' }, el('label', { for: 's01-context', text: 'Application context' }), contextInput),
    el('p', { class: 'ctl' }, el('label', { for: 's01-message', text: 'Message' }), messageInput),
    run,
  ), status);

  const cards = new Map<string, ReturnType<typeof resultCard>>();
  const grid = el('div', { class: 's01-results' });
  for (const line of RESULT_LINES) {
    const card = resultCard(line);
    cards.set(line.id, card);
    grid.append(card.card);
  }
  root.append(grid);

  const trace = el('div', { class: 's01-trace' });
  const evidenceSigned = el('code', { class: 'hexblock', id: 's01-evidence-signed', text: '(run the cases)' });
  const evidenceSignature = el('code', { class: 'hexblock', id: 's01-evidence-signature', text: '(run the cases)' });
  const evidenceKey = el('code', { class: 'hexblock', id: 's01-evidence-key', text: '(run the cases)' });
  const kciEnc = el('code', { class: 'hexblock', id: 's01-kci-enc', text: '(run the cases)' });
  trace.append(
    el('details', { class: 'expert' },
      el('summary', { text: 'Inspect independently verifiable public bytes' }),
      el('p', { class: 'note' },
        'The recipient may disclose these public evidence bytes. A verifier must obtain Sara’s Ed25519 key from a separately trusted identity-to-key mapping; accepting the key bundled with an untrusted receipt would make key substitution trivial.'),
      el('p', { class: 'hexrow' }, el('span', { class: 'hexrow-label', text: 'canonical signed transcript' }), evidenceSigned),
      el('p', { class: 'hexrow' }, el('span', { class: 'hexrow-label', text: 'Ed25519 signature' }), evidenceSignature),
      el('p', { class: 'hexrow' }, el('span', { class: 'hexrow-label', text: 'pinned Sara Ed25519 public key' }), evidenceKey),
      el('p', { class: 'hexrow' }, el('span', { class: 'hexrow-label', text: 'fresh KCI encapsulated key (public enc)' }), kciEnc),
    ),
  );
  root.append(trace);

  const matrixBody = el('tbody', {},
    matrixRow('No long-term key compromised', 'Holds against the modeled outsider', 'Holds under the component assumptions', 'Ciphertext tampering fails HPKE; the signed identity/context tuple verifies.'),
    matrixRow('Recipient HPKE skR compromised', 'Lost for ciphertexts to that key', 'StE sender authenticity remains while Sara’s signing key is safe', 'The executable Auth KCI forgery succeeds; the changed StE message fails Ed25519.'),
    matrixRow('Sender Ed25519 signing key compromised', 'Recorded Base-HPKE ciphertexts remain hidden while skR is safe', 'Lost for new StE messages', 'The stolen signing key creates a fresh transcript; it does not decrypt Ravi’s ciphertexts.'),
    matrixRow('Both keys compromised', 'Lost', 'Lost', 'The attacker can open recorded packets and sign fresh ones.'),
  );
  root.append(
    el('h3', { class: 's01-matrix-heading', text: 'Bounded StE compromise matrix' }),
    el('div', { class: 'tablewrap s01-tablewrap', tabindex: '0', role: 'region', 'aria-label': 'Sign-then-Encrypt compromise matrix' },
      el('table', { class: 's01-matrix' },
        el('thead', {}, el('tr', {},
          el('th', { scope: 'col', text: 'Compromise' }),
          el('th', { scope: 'col', text: 'Confidentiality' }),
          el('th', { scope: 'col', text: 'Sender authenticity' }),
          el('th', { scope: 'col', text: 'Why' }),
        )),
        matrixBody,
      ),
    ),
    el('p', { class: 'note' },
      'Transferability is narrow: the disclosed Ed25519 signature can show that the pinned signing key signed these exact fields. It does not prove ciphertext authorship, transmission, receipt, time, human intent, or legal non-repudiation. A recipient can re-encrypt the same valid signed payload. Replay also remains an application responsibility.'),
  );

  const resetResults = (): void => {
    for (const line of RESULT_LINES) {
      const card = cards.get(line.id)!;
      setChip(card.chip, 'neutral', '·', 'result retired — run again');
      card.note.textContent = line.expectation;
    }
    evidenceSigned.textContent = '(run the cases)';
    evidenceSignature.textContent = '(run the cases)';
    evidenceKey.textContent = '(run the cases)';
    kciEnc.textContent = '(run the cases)';
    status.textContent = 'Inputs changed; prior cryptographic results retired.';
  };
  contextInput.addEventListener('input', resetResults);
  messageInput.addEventListener('input', resetResults);

  run.addEventListener('click', () => {
    void (async () => {
      run.disabled = true;
      contextInput.disabled = true;
      messageInput.disabled = true;
      for (const line of RESULT_LINES) {
        const card = cards.get(line.id)!;
        setChip(card.chip, 'neutral', '·', 'running');
        card.note.textContent = line.expectation;
      }
      evidenceSigned.textContent = '(running)';
      evidenceSignature.textContent = '(running)';
      evidenceKey.textContent = '(running)';
      kciEnc.textContent = '(running)';
      status.textContent = 'Running real X25519 HPKE and Ed25519 cases…';
      try {
        const sara: LessonParty = createParty('Sara');
        const ravi: LessonParty = createParty('Ravi');
        const rita: LessonParty = createParty('Rita');
        const context = contextInput.value;
        const message = messageInput.value;

        const honestAuth = await authSeal(sara, ravi, context, message);
        const honestAuthOpen = await authOpen(honestAuth, ravi, sara, context);
        const honestSte = await signcrypt(sara, ravi, context, message);
        const honestSteOpen = await designcrypt(honestSte, ravi, sara, context);
        const honestOk = honestAuthOpen.accepted && honestSteOpen.accepted;
        verdict(
          cards.get('s01-honest')!.chip,
          honestOk ? 'ok' : 'alarm',
          honestOk ? '✓' : '⚠',
          honestOk ? 'both accepted under the intended bindings' : 'unexpected honest-case failure',
          cards.get('s01-honest')!.note,
          `Auth accepted: ${honestAuthOpen.accepted ? 'yes' : 'no'}; StE accepted: ${honestSteOpen.accepted ? 'yes' : 'no'}.`,
        );

        const outsider = await designcrypt(flipSteCiphertext(honestSte), ravi, sara, context);
        verdict(
          cards.get('s01-outsider')!.chip,
          !outsider.accepted && !outsider.hpkeOpened ? 'ok' : 'alarm',
          !outsider.accepted && !outsider.hpkeOpened ? '✓' : '⚠',
          !outsider.accepted && !outsider.hpkeOpened ? 'rejected before plaintext release' : 'unexpected tamper acceptance',
          cards.get('s01-outsider')!.note,
          acceptedSummary(outsider),
        );

        const authKci = await forgeAuthAfterRecipientCompromise(sara, ravi, context, `${message} [KCI forgery]`);
        const authKciOpen = await authOpen(authKci, ravi, sara, context);
        verdict(
          cards.get('s01-auth-kci')!.chip,
          authKciOpen.accepted ? 'alarm' : 'neutral',
          authKciOpen.accepted ? '⚠' : '·',
          authKciOpen.accepted ? 'forgery accepted — documented KCI limit' : 'forgery did not reproduce',
          cards.get('s01-auth-kci')!.note,
          `The attacker path used Ravi’s skR and Sara’s public pkS, never Sara’s skS. Receiver result: ${authKciOpen.reason}. A valid Auth ciphertext is therefore not transferable proof to a third party that Sara created it.`,
        );
        kciEnc.textContent = bytesToHex(authKci.enc);

        const recipientForgery = await forgeAfterRecipientCompromise(
          honestSte,
          ravi,
          `${message} [recipient changed it]`,
        );
        const recipientForgeryOpen = await designcrypt(recipientForgery, ravi, sara, context);
        const recipientHeld = (
          recipientForgeryOpen.hpkeOpened
          && !recipientForgeryOpen.accepted
          && !recipientForgeryOpen.signatureValid
          && recipientForgeryOpen.fields === null
        );
        verdict(
          cards.get('s01-ste-recipient')!.chip,
          recipientHeld ? 'ok' : 'alarm',
          recipientHeld ? '✓' : '⚠',
          recipientHeld ? 'changed message rejected; plaintext quarantined' : 'unexpected recipient-forgery result',
          cards.get('s01-ste-recipient')!.note,
          `${acceptedSummary(recipientForgeryOpen)} Rejected content was retained only in the learner diagnostic, not returned as application plaintext.`,
        );

        const forwarded = await forwardToAnotherRecipient(honestSte, ravi, rita);
        const forwardedOpen = await designcrypt(forwarded, rita, sara, context);
        const forwardingHeld = (
          forwardedOpen.hpkeOpened
          && forwardedOpen.signatureValid
          && !forwardedOpen.bindingsMatch
          && !forwardedOpen.accepted
        );
        verdict(
          cards.get('s01-forward')!.chip,
          forwardingHeld ? 'ok' : 'alarm',
          forwardingHeld ? '✓' : '⚠',
          forwardingHeld ? 'valid signature, wrong signed recipient — rejected' : 'unexpected forwarding result',
          cards.get('s01-forward')!.note,
          `${acceptedSummary(forwardedOpen)} The quarantined transcript names ${forwardedOpen.diagnosticFields?.recipientId ?? 'no recipient'}.`,
        );

        const stolenSigningCapability = {
          id: sara.id,
          signing: { secretKey: sara.signing.secretKey },
        };
        const raviPublicRecord = { id: ravi.id, hpke: { pk: ravi.hpke.pk } };
        const senderForgery = await signcrypt(
          stolenSigningCapability,
          raviPublicRecord,
          context,
          `${message} [sender key stolen]`,
        );
        const senderForgeryOpen = await designcrypt(senderForgery, ravi, sara, context);
        const senderCannotOpen = await designcrypt(honestSte, sara, sara, context);
        const senderCase = senderForgeryOpen.accepted && !senderCannotOpen.hpkeOpened;
        verdict(
          cards.get('s01-sender')!.chip,
          senderCase ? 'alarm' : 'neutral',
          senderCase ? '⚠' : '·',
          senderCase ? 'new forgery accepted; recorded ciphertext stayed closed' : 'unexpected sender-compromise result',
          cards.get('s01-sender')!.note,
          `Fresh forgery accepted: ${senderForgeryOpen.accepted ? 'yes' : 'no'}; opening the recorded Ravi ciphertext with sender-side keys: ${senderCannotOpen.hpkeOpened ? 'succeeded' : 'failed'}.`,
        );

        const bothOpenedRecorded = await designcrypt(honestSte, ravi, sara, context);
        const bothForgedFresh = await designcrypt(
          await signcrypt(sara, ravi, context, `${message} [both keys compromised]`),
          ravi,
          sara,
          context,
        );
        const bothLost = bothOpenedRecorded.accepted && bothForgedFresh.accepted;
        verdict(
          cards.get('s01-both')!.chip,
          bothLost ? 'alarm' : 'neutral',
          bothLost ? '⚠' : '·',
          bothLost ? 'recorded plaintext exposed; fresh forgery accepted' : 'combined compromise did not reproduce',
          cards.get('s01-both')!.note,
          `Recorded packet opened with skR: ${bothOpenedRecorded.accepted ? 'yes' : 'no'}; fresh packet created with the stolen signing key and accepted: ${bothForgedFresh.accepted ? 'yes' : 'no'}.`,
        );

        const evidence = honestSteOpen.evidence;
        const evidenceResult = evidence
          ? verifyTransferEvidence(evidence, sara, ravi.id, context)
          : { valid: false };
        verdict(
          cards.get('s01-evidence')!.chip,
          evidenceResult.valid ? 'ok' : 'alarm',
          evidenceResult.valid ? '✓' : '⚠',
          evidenceResult.valid ? 'signature verifies under the pinned Sara key' : 'evidence verification failed',
          cards.get('s01-evidence')!.note,
          evidenceResult.valid
            ? 'Verification required only the disclosed transcript/signature and the separately trusted Sara public key — not Ravi’s HPKE private key.'
            : 'The honest evidence was unexpectedly unavailable or invalid.',
        );
        if (evidence) {
          evidenceSigned.textContent = bytesToHex(evidence.signedBytes);
          evidenceSignature.textContent = bytesToHex(evidence.signature);
          evidenceKey.textContent = bytesToHex(sara.signing.publicKey);
        }

        const replayFirst = await designcrypt(honestSte, ravi, sara, context);
        const replaySecond = await designcrypt(honestSte, ravi, sara, context);
        const replayed = replayFirst.accepted && replaySecond.accepted;
        verdict(
          cards.get('s01-replay')!.chip,
          replayed ? 'alarm' : 'neutral',
          replayed ? '⚠' : '·',
          replayed ? 'accepted twice — application replay state required' : 'second delivery did not open',
          cards.get('s01-replay')!.note,
          `First delivery accepted: ${replayFirst.accepted ? 'yes' : 'no'}; second delivery accepted: ${replaySecond.accepted ? 'yes' : 'no'}. No message identifier or replay cache is part of this teaching profile.`,
        );

        status.textContent = 'Nine cases completed from fresh keys. Alarm-colored results mark demonstrated compromise limits, not test failures.';
      } catch (error) {
        for (const line of RESULT_LINES) {
          const card = cards.get(line.id)!;
          if (card.chip.textContent?.includes('running')) {
            setChip(card.chip, 'neutral', '·', 'not completed');
          }
        }
        evidenceSigned.textContent = '(not completed)';
        evidenceSignature.textContent = '(not completed)';
        evidenceKey.textContent = '(not completed)';
        kciEnc.textContent = '(not completed)';
        status.textContent = `Cases stopped safely: ${error instanceof Error ? error.message : String(error)}`;
      } finally {
        run.disabled = false;
        contextInput.disabled = false;
        messageInput.disabled = false;
      }
    })();
  });

  return root;
}
