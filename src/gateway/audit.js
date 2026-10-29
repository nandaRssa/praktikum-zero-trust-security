const fs = require('fs');
const config = require('../config');
const { getDatabase } = require('../database/connection');

function logAudit({ subject, endpoint, method, device, decision, reason, ip }) {
  const timestamp = new Date().toISOString();
  const sub = subject || 'anonymous';
  const dev = device || '-';
  const ipAddr = ip || '127.0.0.1';

  try {
    // 1. Simpan ke Database
    const db = getDatabase();
    const stmt = db.prepare(`
      INSERT INTO audit_logs (timestamp, subject, endpoint, method, device, decision, reason, ip_address)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(timestamp, sub, endpoint, method, dev, decision, reason, ipAddr);

    // 2. Tulis ke File audit.log
    const logLine = `[${timestamp}] [${decision.padEnd(5)}] [SUB: ${sub}] [${method.toUpperCase()} ${endpoint}] [DEV: ${dev}] Reason: ${reason}\n`;
    fs.appendFileSync(config.audit.logFile, logLine, 'utf8');

    // Console output untuk visualisasi real-time
    const color = decision === 'ALLOW' ? '\x1b[32m' : '\x1b[31m';
    console.log(`${color}[AUDIT ${decision}]\x1b[0m ${method.toUpperCase()} ${endpoint} | Sub: ${sub} | Dev: ${dev} | Reason: ${reason}`);
  } catch (error) {
    console.error('[AUDIT ERROR] Gagal mencatat audit log:', error.message);
  }
}

module.exports = {
  logAudit
};
