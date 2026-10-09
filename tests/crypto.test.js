'use strict';
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { test } = require('node:test');
const assert   = require('node:assert/strict');
const { generate, decrypt } = require('../lib/crypto');
const { scan, summary }     = require('../lib/scanner');

// ── Crypto engine ─────────────────────────────────────────────────────────────

test('RSA-4096 generates public and encrypted private key', () => {
  const r = generate({ algorithm: 'RSA', key_size: 4096 });
  assert.ok(r.public_key.startsWith('-----BEGIN PUBLIC KEY-----'));
  assert.ok(r.key_material.includes(':'));
  assert.ok(r.fingerprint.length === 64);
  const priv = decrypt(r.key_material);
  assert.ok(priv.startsWith('-----BEGIN PRIVATE KEY-----'));
});

test('RSA-2048 generates valid keypair', () => {
  const r = generate({ algorithm: 'RSA', key_size: 2048 });
  assert.ok(r.public_key.includes('PUBLIC KEY'));
});

test('EC P-256 generates public and private key', () => {
  const r = generate({ algorithm: 'EC', curve: 'P-256' });
  assert.ok(r.public_key.startsWith('-----BEGIN PUBLIC KEY-----'));
  const priv = decrypt(r.key_material);
  assert.ok(priv.startsWith('-----BEGIN PRIVATE KEY-----'));
});

test('EC P-384 generates valid keypair', () => {
  const r = generate({ algorithm: 'EC', curve: 'P-384' });
  assert.ok(r.public_key.includes('PUBLIC KEY'));
});

test('AES-256 generates encrypted key material', () => {
  const r = generate({ algorithm: 'AES', key_size: 256 });
  assert.strictEqual(r.public_key, null);
  assert.ok(r.key_material.includes(':'));
  const hex = decrypt(r.key_material);
  assert.strictEqual(hex.length, 64); // 32 bytes = 64 hex chars
});

test('AES-128 generates 32-char hex key', () => {
  const r = generate({ algorithm: 'AES', key_size: 128 });
  const hex = decrypt(r.key_material);
  assert.strictEqual(hex.length, 32);
});

test('HMAC-SHA256 generates key material', () => {
  const r = generate({ algorithm: 'HMAC', hash_alg: 'SHA-256' });
  assert.strictEqual(r.public_key, null);
  const hex = decrypt(r.key_material);
  assert.strictEqual(hex.length, 64); // 32 bytes
});

test('HMAC-SHA512 generates 64-byte key', () => {
  const r = generate({ algorithm: 'HMAC', hash_alg: 'SHA-512' });
  const hex = decrypt(r.key_material);
  assert.strictEqual(hex.length, 128); // 64 bytes
});

test('Fingerprints are unique per generation', () => {
  const a = generate({ algorithm: 'AES', key_size: 256 });
  const b = generate({ algorithm: 'AES', key_size: 256 });
  assert.notStrictEqual(a.fingerprint, b.fingerprint);
});

test('Decrypt returns original plaintext', () => {
  const r = generate({ algorithm: 'AES', key_size: 256 });
  const plain = decrypt(r.key_material);
  assert.strictEqual(plain.length, 64);
  assert.match(plain, /^[0-9a-f]+$/);
});

test('Unknown algorithm throws', () => {
  assert.throws(() => generate({ algorithm: 'DES' }), /Unknown algorithm/);
});

// ── Vulnerability scanner ─────────────────────────────────────────────────────

const now = Date.now();

test('Flags RSA < 2048 as CRITICAL', () => {
  const findings = scan([{ id:'1', name:'weak', algorithm:'RSA', key_size:1024, status:'active', expires_at: now + 999999999 }]);
  assert.ok(findings.some(f => f.rule_id === 'rsa-weak-key' && f.severity === 'CRITICAL'));
});

test('Passes RSA-2048', () => {
  const findings = scan([{ id:'2', name:'ok', algorithm:'RSA', key_size:2048, status:'active', expires_at: now + 999999999 }]);
  assert.ok(!findings.some(f => f.rule_id === 'rsa-weak-key'));
});

test('Flags expired key as HIGH', () => {
  const findings = scan([{ id:'3', name:'exp', algorithm:'AES', key_size:256, status:'active', expires_at: now - 1000, notes: null }]);
  assert.ok(findings.some(f => f.rule_id === 'key-expired' && f.severity === 'HIGH'));
});

test('Flags key expiring in 15 days as MEDIUM', () => {
  const findings = scan([{ id:'4', name:'soon', algorithm:'AES', key_size:256, status:'active', expires_at: now + 15 * 86400000, notes: null }]);
  assert.ok(findings.some(f => f.rule_id === 'key-expiring-soon' && f.severity === 'MEDIUM'));
});

test('Flags key with no expiry as LOW', () => {
  const findings = scan([{ id:'5', name:'noexp', algorithm:'AES', key_size:256, status:'active', expires_at: null, notes: null, created_at: now }]);
  assert.ok(findings.some(f => f.rule_id === 'no-expiry' && f.severity === 'LOW'));
});

test('Flags HMAC SHA-1 as HIGH', () => {
  const findings = scan([{ id:'6', name:'sha1', algorithm:'HMAC', key_size:null, status:'active', expires_at: now + 999999999, notes: 'SHA-1' }]);
  assert.ok(findings.some(f => f.rule_id === 'hmac-sha1' && f.severity === 'HIGH'));
});

test('Flags deprecated EC curve P-192 as HIGH', () => {
  const findings = scan([{ id:'7', name:'p192', algorithm:'EC', curve:'P-192', status:'active', expires_at: now + 999999999 }]);
  assert.ok(findings.some(f => f.rule_id === 'ec-weak-curve' && f.severity === 'HIGH'));
});

test('Flags AES < 128 as HIGH', () => {
  const findings = scan([{ id:'8', name:'weakaes', algorithm:'AES', key_size:64, status:'active', expires_at: now + 999999999 }]);
  assert.ok(findings.some(f => f.rule_id === 'aes-weak-key' && f.severity === 'HIGH'));
});

test('Does not flag revoked key for expiry', () => {
  const findings = scan([{ id:'9', name:'rev', algorithm:'AES', key_size:256, status:'revoked', expires_at: now - 1000 }]);
  assert.ok(!findings.some(f => f.rule_id === 'key-expired'));
});

test('Summary counts severities correctly', () => {
  const findings = [
    { severity: 'CRITICAL' }, { severity: 'HIGH' }, { severity: 'HIGH' }, { severity: 'LOW' }
  ];
  const s = summary(findings);
  assert.strictEqual(s.CRITICAL, 1);
  assert.strictEqual(s.HIGH, 2);
  assert.strictEqual(s.LOW, 1);
  assert.strictEqual(s.MEDIUM, 0);
});
