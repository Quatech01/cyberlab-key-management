'use strict';
require('dotenv').config();
const express = require('express');
const path    = require('path');
const db      = require('./lib/db');
const crypto  = require('./lib/crypto');
const scanner = require('./lib/scanner');
const audit   = require('./lib/audit');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function ip(req) { return req.ip || req.socket?.remoteAddress || null; }

const ALGORITHMS = {
  RSA:  { sizes: [1024, 2048, 4096] },
  EC:   { curves: ['P-256', 'P-384', 'P-521', 'P-192', 'secp256k1'] },
  AES:  { sizes: [64, 128, 192, 256] },
  HMAC: { hashes: ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] },
};
const PURPOSES = ['encryption', 'signing', 'authentication', 'key-wrapping', 'general'];

function validate(body) {
  const { name, algorithm, key_size, curve, hash_alg, purpose } = body;
  if (!name?.trim())               return 'name is required';
  if (!ALGORITHMS[algorithm])      return `algorithm must be one of: ${Object.keys(ALGORITHMS).join(', ')}`;
  if (!PURPOSES.includes(purpose)) return `purpose must be one of: ${PURPOSES.join(', ')}`;
  if (algorithm === 'RSA' && !ALGORITHMS.RSA.sizes.includes(key_size))
    return `RSA key_size must be one of: ${ALGORITHMS.RSA.sizes.join(', ')}`;
  if (algorithm === 'EC' && !ALGORITHMS.EC.curves.includes(curve))
    return `EC curve must be one of: ${ALGORITHMS.EC.curves.join(', ')}`;
  if (algorithm === 'AES' && !ALGORITHMS.AES.sizes.includes(key_size))
    return `AES key_size must be one of: ${ALGORITHMS.AES.sizes.join(', ')}`;
  if (algorithm === 'HMAC' && hash_alg && !ALGORITHMS.HMAC.hashes.includes(hash_alg))
    return `HMAC hash_alg must be one of: ${ALGORITHMS.HMAC.hashes.join(', ')}`;
  return null;
}

// List keys
app.get('/api/keys', (req, res) => {
  const keys = db.getKeys({ status: req.query.status, algorithm: req.query.algorithm });
  res.json(keys.map(k => { const { key_material, ...safe } = k; return safe; }));
});

// Get single key
app.get('/api/keys/:id', (req, res) => {
  const key = db.getKey(req.params.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });
  const { key_material, ...safe } = key;
  audit.log(key.id, 'viewed', null, ip(req));
  res.json(safe);
});

// Generate key
app.post('/api/keys/generate', (req, res) => {
  const err = validate(req.body);
  if (err) return res.status(400).json({ error: err });

  const { name, algorithm, key_size, curve, hash_alg, purpose, expires_in_days, tags, notes } = req.body;

  let material;
  try { material = crypto.generate({ algorithm, key_size, curve, hash_alg }); }
  catch (e) { return res.status(500).json({ error: e.message }); }

  const id         = crypto.generateId();
  const created_at = Date.now();
  const expires_at = expires_in_days ? created_at + expires_in_days * 86400000 : null;
  const notesStr   = algorithm === 'HMAC'
    ? `${hash_alg || 'SHA-256'}${notes ? ' — ' + notes : ''}`
    : (notes || null);

  const key = {
    id, name: name.trim(), algorithm,
    key_size:    key_size || null,
    curve:       curve    || null,
    purpose, status: 'active', created_at, expires_at,
    rotated_from: null,
    public_key:   material.public_key,
    key_material: material.key_material,
    fingerprint:  material.fingerprint,
    tags: tags || [],
    notes: notesStr,
  };

  db.saveKey(key);
  audit.log(id, 'generated', { algorithm, key_size, curve, hash_alg, purpose }, ip(req));

  const { key_material: _km, ...safe } = key;
  res.status(201).json(safe);
});

// Revoke key
app.patch('/api/keys/:id/revoke', (req, res) => {
  const key = db.getKey(req.params.id);
  if (!key)                    return res.status(404).json({ error: 'Key not found' });
  if (key.status !== 'active') return res.status(400).json({ error: `Key is already ${key.status}` });
  db.updateKeyStatus(key.id, 'revoked');
  audit.log(key.id, 'revoked', { reason: req.body.reason || null }, ip(req));
  res.json({ message: 'Key revoked' });
});

// Rotate key
app.post('/api/keys/:id/rotate', (req, res) => {
  const old = db.getKey(req.params.id);
  if (!old)                   return res.status(404).json({ error: 'Key not found' });
  if (old.status !== 'active') return res.status(400).json({ error: 'Only active keys can be rotated' });

  let material;
  try { material = crypto.generate({ algorithm: old.algorithm, key_size: old.key_size, curve: old.curve }); }
  catch (e) { return res.status(500).json({ error: e.message }); }

  const newId      = crypto.generateId();
  const created_at = Date.now();
  const expires_at = old.expires_at ? created_at + (old.expires_at - old.created_at) : null;

  db.updateKeyStatus(old.id, 'rotated');
  const newKey = {
    id: newId, name: old.name, algorithm: old.algorithm,
    key_size: old.key_size, curve: old.curve, purpose: old.purpose,
    status: 'active', created_at, expires_at,
    rotated_from: old.id,
    public_key:   material.public_key,
    key_material: material.key_material,
    fingerprint:  material.fingerprint,
    tags: old.tags, notes: old.notes,
  };
  db.saveKey(newKey);

  audit.log(old.id,  'rotated-out', { replaced_by: newId }, ip(req));
  audit.log(newId,   'rotated-in',  { replaces: old.id },   ip(req));

  const { key_material: _km, ...safe } = newKey;
  res.status(201).json(safe);
});

// Export public key
app.get('/api/keys/:id/export', (req, res) => {
  const key = db.getKey(req.params.id);
  if (!key)            return res.status(404).json({ error: 'Key not found' });
  if (!key.public_key) return res.status(400).json({ error: 'No public key for this key type' });
  audit.log(key.id, 'exported', null, ip(req));
  res.type('text/plain').send(key.public_key);
});

// Vulnerability scan
app.get('/api/scan', (_req, res) => {
  const keys     = db.allKeys();
  const findings = scanner.scan(keys);
  res.json({ findings, summary: scanner.summary(findings) });
});

// Audit log
app.get('/api/audit',         (req, res) => res.json(audit.recent(Math.min(parseInt(req.query.limit) || 100, 500))));
app.get('/api/audit/:key_id', (req, res) => res.json(audit.forKey(req.params.key_id)));

// Stats
app.get('/api/stats', (_req, res) => {
  const keys = db.allKeys();
  const now  = Date.now();
  const byAlgo = {}, byStatus = {};
  let expiringSoon = 0, expired = 0;
  for (const k of keys) {
    byAlgo[k.algorithm]   = (byAlgo[k.algorithm]   || 0) + 1;
    byStatus[k.status]    = (byStatus[k.status]     || 0) + 1;
    if (k.expires_at && k.expires_at < now)                      expired++;
    else if (k.expires_at && k.expires_at < now + 30*86400000)   expiringSoon++;
  }
  const findings = scanner.scan(keys);
  res.json({ total: keys.length, by_algorithm: byAlgo, by_status: byStatus, expiring_soon: expiringSoon, expired, vulnerabilities: scanner.summary(findings) });
});

const PORT = process.env.PORT || 3007;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Key Management System on http://localhost:${PORT}`));
}
module.exports = app;
