'use strict';
const db = require('./db');

function log(key_id, action, details = null, ip = null) {
  const key = db.getKey(key_id);
  db.logAudit({
    key_id,
    key_name:  key ? key.name : null,
    algorithm: key ? key.algorithm : null,
    action,
    details:   details ? JSON.stringify(details) : null,
    ip,
    ts: Date.now(),
  });
}

function recent(limit = 100) { return db.getAudit(limit); }
function forKey(key_id)       { return db.getAuditForKey(key_id); }

module.exports = { log, recent, forKey };
