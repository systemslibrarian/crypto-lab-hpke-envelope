/** Sibling labs this demo links out to instead of rebuilding (scope guard). */
const gh = (repo: string) => `https://systemslibrarian.github.io/${repo}/`;

export const LABS = {
  catalog: 'https://crypto-lab.systemslibrarian.dev/',
  kyberVault: gh('crypto-lab-kyber-vault'),
  curveLens: gh('crypto-lab-curve-lens'),
  kdfChain: gh('crypto-lab-kdf-chain'),
  aesModes: gh('crypto-lab-aes-modes'),
  ascon: gh('crypto-lab-ascon'),
  aegisGate: gh('crypto-lab-aegis-gate'),
  nonceCollision: gh('crypto-lab-nonce-collision'),
  hybridWire: gh('crypto-lab-hybrid-wire'),
  entropyCollapse: gh('crypto-lab-entropy-collapse'),
  blindHello: gh('crypto-lab-blind-hello'), // ECH
  blindRelay: gh('crypto-lab-blind-relay'), // OHTTP
  downgradeWire: gh('crypto-lab-downgrade-wire'),
  ratchetWire: gh('crypto-lab-ratchet-wire'),
} as const;
