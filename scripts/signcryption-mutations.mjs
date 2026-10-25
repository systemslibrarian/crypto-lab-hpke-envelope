#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const sourcePath = fileURLToPath(new URL('../src/signcryption/ste.ts', import.meta.url));
const vitest = fileURLToPath(new URL('../node_modules/vitest/vitest.mjs', import.meta.url));
const original = readFileSync(sourcePath, 'utf8');

const bindingBlock = `const bindingsMatch = (
      packet.senderId === expectedSender.id
      && fields.senderId === packet.senderId
      && fields.recipientId === packet.recipientId
      && fields.context === packet.context
      && packet.recipientId === recipient.id
      && packet.context === expectedContext
    );`;

const bindingMutations = [
  ['outer sender to trusted sender', 'packet.senderId === expectedSender.id'],
  ['signed sender to outer sender', 'fields.senderId === packet.senderId'],
  ['signed recipient to outer recipient', 'fields.recipientId === packet.recipientId'],
  ['signed context to outer context', 'fields.context === packet.context'],
  ['outer recipient to local recipient', 'packet.recipientId === recipient.id'],
  ['packet context to independently expected context', 'packet.context === expectedContext'],
].map(([label, clause]) => ({
  name: `skip ${label} binding`,
  from: bindingBlock,
  to: bindingBlock.replace(clause, 'true'),
}));

const evidenceTrustBlock = `const trustedKeyMatches = (
      evidence.senderId === expectedSender.id
      && fields.senderId === expectedSender.id
      && fields.recipientId === expectedRecipientId
      && fields.context === expectedContext
      && equalBytes(evidence.senderPublicKey, expectedSender.signing.publicKey)
    );`;

const evidenceExpectationMutations = [
  ['evidence recipient', 'fields.recipientId === expectedRecipientId'],
  ['evidence application context', 'fields.context === expectedContext'],
].map(([label, clause]) => ({
  name: `skip expected ${label} binding`,
  from: evidenceTrustBlock,
  to: evidenceTrustBlock.replace(clause, 'true'),
}));

const mutations = [
  {
    name: 'permit ZIP-215 verification instead of strict RFC 8032 verification',
    from: 'return ed25519.verify(signature, message, publicKey, { zip215: false });',
    to: 'return ed25519.verify(signature, message, publicKey, { zip215: true });',
  },
  {
    name: 'accept trailing bytes in a framed tuple',
    from: "if (offset !== encoded.length) throw new Error('tuple has trailing bytes');",
    to: "if (offset > encoded.length) throw new Error('tuple has trailing bytes');",
  },
  {
    name: 'release rejected plaintext to the application',
    from: 'fields: accepted ? fields : null,',
    to: 'fields,',
  },
  {
    name: 'release transfer evidence before all checks pass',
    from: 'evidence: accepted ? evidence : null,',
    to: 'evidence,',
  },
  ...bindingMutations,
  ...evidenceExpectationMutations,
  {
    name: 'accept every decrypted signature',
    from: 'const signatureValid = strictVerify(signature, signedBytes, expectedSender.signing.publicKey);',
    to: 'const signatureValid = true;',
  },
  {
    name: 'trust the sender identity and key bundled with disclosed evidence',
    from: `const trustedKeyMatches = (
      evidence.senderId === expectedSender.id
      && fields.senderId === expectedSender.id
      && fields.recipientId === expectedRecipientId
      && fields.context === expectedContext
      && equalBytes(evidence.senderPublicKey, expectedSender.signing.publicKey)
    );
    const valid = (
      fieldsAgree
      && trustedKeyMatches
      && strictVerify(
        evidence.signature,
        evidence.signedBytes,
        expectedSender.signing.publicKey,
      )
    );`,
    to: `const trustedKeyMatches = true;
    const valid = (
      fieldsAgree
      && trustedKeyMatches
      && strictVerify(
        evidence.signature,
        evidence.signedBytes,
        evidence.senderPublicKey,
      )
    );`,
  },
  {
    name: 'return decoded fields from invalid transfer evidence',
    from: 'fields: valid ? fields : null,',
    to: 'fields,',
  },
  {
    name: 'release HPKE Auth plaintext despite an identity mismatch',
    from: "message: bindingsMatch ? message : '',",
    to: 'message,',
  },
  {
    name: 'skip HPKE Auth expected application-context binding',
    from: `const bindingsMatch = (
      packet.senderId === expectedSender.id
      && packet.recipientId === recipient.id
      && packet.context === expectedContext
    );`,
    to: `const bindingsMatch = (
      packet.senderId === expectedSender.id
      && packet.recipientId === recipient.id
      && true
    );`,
  },
  {
    name: 'weaken the message-size bound by one byte',
    from: 'const MAX_MESSAGE_BYTES = 4096;',
    to: 'const MAX_MESSAGE_BYTES = 4097;',
  },
  {
    name: 'derive the KCI forgery under the wrong HPKE mode',
    from: `const schedule = keySchedule(
    MODE_AUTH,
    AEAD_AES_128_GCM,
    kem.sharedSecret,
    authInfo(shell),
  );`,
    to: `const schedule = keySchedule(
    MODE_BASE,
    AEAD_AES_128_GCM,
    kem.sharedSecret,
    authInfo(shell),
  );`,
  },
];

function runFocusedTests() {
  return spawnSync(process.execPath, [vitest, 'run', 'src/signcryption/ste.test.ts'], {
    cwd: root,
    encoding: 'utf8',
    stdio: 'pipe',
  });
}

function replaceExactly(source, mutation) {
  const first = source.indexOf(mutation.from);
  if (first < 0) throw new Error(`mutation anchor missing: ${mutation.name}`);
  if (source.indexOf(mutation.from, first + mutation.from.length) >= 0) {
    throw new Error(`mutation anchor is not unique: ${mutation.name}`);
  }
  return source.slice(0, first) + mutation.to + source.slice(first + mutation.from.length);
}

let caught = 0;
try {
  const baseline = runFocusedTests();
  if (baseline.status !== 0) {
    process.stderr.write(baseline.stdout);
    process.stderr.write(baseline.stderr);
    throw new Error('baseline: unmutated copy FAILED; mutation results are meaningless');
  }
  console.log('baseline: unmutated copy PASSES');

  for (const mutation of mutations) {
    writeFileSync(sourcePath, replaceExactly(original, mutation), 'utf8');
    const result = runFocusedTests();
    writeFileSync(sourcePath, original, 'utf8');
    if (result.status === 0) {
      process.stderr.write(result.stdout);
      process.stderr.write(result.stderr);
      throw new Error(`mutation survived: ${mutation.name}`);
    }
    caught++;
    console.log(`caught: ${mutation.name}`);
  }
} finally {
  writeFileSync(sourcePath, original, 'utf8');
}

console.log(`all ${caught} mutation(s) caught`);
