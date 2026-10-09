'use strict';
const fs   = require('fs');
const path = require('path');

const DATA_FILE  = path.join(__dirname, '..', 'keys.json');
const AUDIT_FILE = path.join(__dirname, '..', 'audit.json');

function readJSON(file, def) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return def; }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ── Keys ──────────────────────────────────────────────────────────────────────
const db = {
  getKeys(filters = {}) {
    let keys = readJSON(DATA_FILE, []);
    if (filters.status)    keys = keys.filter(k => k.status    === filters.status);
    if (filters.algorithm) keys = keys.filter(k => k.algorithm === filters.algorithm);
    return keys.sort((a, b) => b.created_at - a.created_at);
  },
  getKey(id) {
    return readJSON(DATA_FILE, []).find(k => k.id === id) || null;
  },
  saveKey(key) {
    const keys = readJSON(DATA_FILE, []);
    const idx  = keys.findIndex(k => k.id === key.id);
    if (idx >= 0) keys[idx] = key; else keys.push(key);
    writeJSON(DATA_FILE, keys);
  },
  updateKeyStatus(id, status) {
    const keys = readJSON(DATA_FILE, []);
    const key  = keys.find(k => k.id === id);
    if (key) { key.status = status; writeJSON(DATA_FILE, keys); }
  },
  allKeys() {
    return readJSON(DATA_FILE, []);
  },

  // ── Audit ──────────────────────────────────────────────────────────────────
  logAudit(entry) {
    const logs = readJSON(AUDIT_FILE, []);
    logs.unshift({ id: Date.now() + Math.random(), ...entry });
    if (logs.length > 2000) logs.splice(2000);
    writeJSON(AUDIT_FILE, logs);
  },
  getAudit(limit = 100) {
    return readJSON(AUDIT_FILE, []).slice(0, limit);
  },
  getAuditForKey(key_id) {
    return readJSON(AUDIT_FILE, []).filter(l => l.key_id === key_id);
  },
};

module.exports = db;
