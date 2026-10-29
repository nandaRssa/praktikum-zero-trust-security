const Database = require('better-sqlite3');
const config = require('../config');

let dbInstance = null;

function getDatabase() {
  if (!dbInstance) {
    dbInstance = new Database(config.database.path);
    dbInstance.pragma('journal_mode = WAL');
    dbInstance.pragma('foreign_keys = ON');
    initSchema(dbInstance);
  }
  return dbInstance;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'dosen', 'mahasiswa')),
      identifier TEXT NOT NULL, -- NIM (mahasiswa), NIDN (dosen), or ADMIN
      nama TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE (user_id, device_id)
    );

    CREATE TABLE IF NOT EXISTS service_clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id TEXT UNIQUE NOT NULL,
      client_secret TEXT NOT NULL,
      service_name TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL,
      revoked INTEGER DEFAULT 0,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS kelas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kode_mk TEXT NOT NULL,
      nama_mk TEXT NOT NULL,
      sks INTEGER NOT NULL DEFAULT 3,
      dosen_id INTEGER NOT NULL,
      is_final INTEGER DEFAULT 0,
      finalized_at DATETIME,
      FOREIGN KEY (dosen_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS nilai (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kelas_id INTEGER NOT NULL,
      mahasiswa_id INTEGER NOT NULL,
      nilai_angka REAL NOT NULL,
      nilai_huruf TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (kelas_id) REFERENCES kelas(id),
      FOREIGN KEY (mahasiswa_id) REFERENCES users(id),
      UNIQUE (kelas_id, mahasiswa_id)
    );

    CREATE TABLE IF NOT EXISTS transkrip (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mahasiswa_id INTEGER NOT NULL,
      nim TEXT NOT NULL,
      kode_mk TEXT NOT NULL,
      nama_mk TEXT NOT NULL,
      sks INTEGER NOT NULL DEFAULT 3,
      nilai_huruf TEXT NOT NULL,
      synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (mahasiswa_id) REFERENCES users(id),
      UNIQUE (mahasiswa_id, kode_mk)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      subject TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      method TEXT NOT NULL,
      device TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'DENY')),
      reason TEXT NOT NULL,
      ip_address TEXT
    );
  `);
}

module.exports = {
  getDatabase
};
