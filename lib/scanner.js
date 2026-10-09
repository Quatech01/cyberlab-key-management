'use strict';

const RULES = [
  {
    id: 'rsa-weak-key',
    severity: 'CRITICAL',
    title: 'RSA key size below 2048 bits',
    description: 'RSA keys smaller than 2048 bits are considered broken. NIST deprecated 1024-bit RSA in 2013.',
    match: k => k.algorithm === 'RSA' && k.key_size < 2048,
  },
  {
    id: 'aes-weak-key',
    severity: 'HIGH',
    title: 'AES key size below 128 bits',
    description: 'AES-128 is the minimum secure key size. Smaller sizes are trivially brute-forced.',
    match: k => k.algorithm === 'AES' && k.key_size < 128,
  },
  {
    id: 'hmac-sha1',
    severity: 'HIGH',
    title: 'HMAC using SHA-1',
    description: 'SHA-1 is collision-vulnerable (SHAttered, 2017). Migrate to SHA-256 or SHA-512.',
    match: k => k.algorithm === 'HMAC' && k.notes && k.notes.includes('SHA-1'),
  },
  {
    id: 'ec-weak-curve',
    severity: 'HIGH',
    title: 'EC key using deprecated curve',
    description: 'P-192 and secp256k1 are not recommended. Use P-256, P-384, or P-521.',
    match: k => k.algorithm === 'EC' && ['P-192', 'secp256k1'].includes(k.curve),
  },
  {
    id: 'key-expired',
    severity: 'HIGH',
    title: 'Key has passed its expiry date',
    description: 'This key is expired and should be revoked and replaced immediately.',
    match: k => k.expires_at && k.expires_at < Date.now() && k.status === 'active',
  },
  {
    id: 'key-expiring-soon',
    severity: 'MEDIUM',
    title: 'Key expiring within 30 days',
    description: 'Schedule rotation before this key expires to avoid service disruption.',
    match: k => k.expires_at && k.expires_at > Date.now() && k.expires_at < Date.now() + 30 * 86400000 && k.status === 'active',
  },
  {
    id: 'no-expiry',
    severity: 'LOW',
    title: 'Key has no expiry date set',
    description: 'Keys without expiry dates accumulate risk over time. Set a rotation schedule.',
    match: k => !k.expires_at && k.status === 'active',
  },
  {
    id: 'key-old',
    severity: 'MEDIUM',
    title: 'Key older than 1 year without rotation',
    description: 'Cryptographic best practice recommends rotating keys at least annually.',
    match: k => k.status === 'active' && (Date.now() - k.created_at) > 365 * 86400000,
  },
];

function scan(keys) {
  const findings = [];
  for (const key of keys) {
    for (const rule of RULES) {
      if (rule.match(key)) {
        findings.push({
          key_id:      key.id,
          key_name:    key.name,
          rule_id:     rule.id,
          severity:    rule.severity,
          title:       rule.title,
          description: rule.description,
        });
      }
    }
  }
  return findings;
}

function summary(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

module.exports = { scan, summary };
