'use strict';
const crypto = require('crypto');

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY || crypto.randomBytes(32).toString('hex'), 'hex');

function generateId() {
  return crypto.randomUUID();
}

function fingerprint(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Encrypt symmetric key material with AES-256-GCM using master key
function encrypt(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, enc].map(b => b.toString('hex')).join(':');
}

function decrypt(blob) {
  const [ivHex, tagHex, encHex] = blob.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const enc = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

function generateRSA(keySize) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return {
    public_key:   publicKey,
    key_material: encrypt(privateKey),
    fingerprint:  fingerprint(publicKey),
  };
}

function generateEC(curve) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: curve,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return {
    public_key:   publicKey,
    key_material: encrypt(privateKey),
    fingerprint:  fingerprint(publicKey),
  };
}

function generateAES(keySize) {
  const key = crypto.randomBytes(keySize / 8);
  const hex = key.toString('hex');
  return {
    public_key:   null,
    key_material: encrypt(hex),
    fingerprint:  fingerprint(hex),
  };
}

function generateHMAC(hashAlg) {
  const sizes = { 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };
  const key = crypto.randomBytes(sizes[hashAlg] || 32);
  const hex = key.toString('hex');
  return {
    public_key:   null,
    key_material: encrypt(hex),
    fingerprint:  fingerprint(hex),
  };
}

function generate({ algorithm, key_size, curve, hash_alg }) {
  switch (algorithm) {
    case 'RSA':  return generateRSA(key_size);
    case 'EC':   return generateEC(curve);
    case 'AES':  return generateAES(key_size);
    case 'HMAC': return generateHMAC(hash_alg || 'SHA-256');
    default:     throw new Error(`Unknown algorithm: ${algorithm}`);
  }
}

function exportPublicKey(key) {
  if (!key.public_key) throw new Error('No public key available for this key type');
  return key.public_key;
}

module.exports = { generateId, generate, decrypt, exportPublicKey };
