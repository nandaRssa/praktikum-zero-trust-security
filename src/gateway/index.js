const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');

const config = require('../config');
const { getDatabase } = require('../database/connection');
const policyEngine = require('./policy');
const { logAudit } = require('./audit');

const app = express();
app.use(express.json());

const db = getDatabase();

// =========================================================================
// 1. ENDPOINT AUTENTIKASI GATEWAY (/auth/*) - Policy Administrator (PA)
// =========================================================================

/**
 * POST /auth/login
 * Memeriksa kredensial user dan device terdaftar
 */
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body;
  const deviceId = req.headers['x-device-id'];
  const endpoint = '/auth/login';
  const method = 'POST';

  if (!username || !password) {
    logAudit({
      subject: username || 'anonymous',
      endpoint,
      method,
      device: deviceId || '-',
      decision: 'DENY',
      reason: 'Username dan password wajib diisi',
      ip: req.ip
    });
    return res.status(400).json({ error: 'Username dan password wajib diisi' });
  }

  // Verifikasi Konteks: Device ID wajib ada
  if (!deviceId) {
    logAudit({
      subject: username,
      endpoint,
      method,
      device: '-',
      decision: 'DENY',
      reason: 'Header X-Device-ID wajib disertakan saat login',
      ip: req.ip
    });
    return res.status(400).json({
      error: 'Header X-Device-ID wajib disertakan saat login',
      code: 'DEVICE_HEADER_MISSING'
    });
  }

  // Cari user di database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    logAudit({
      subject: username,
      endpoint,
      method,
      device: deviceId,
      decision: 'DENY',
      reason: `User '${username}' tidak ditemukan di sistem`,
      ip: req.ip
    });
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }

  // Verifikasi Password (bcrypt)
  const passwordValid = bcrypt.compareSync(password, user.password);
  if (!passwordValid) {
    logAudit({
      subject: username,
      endpoint,
      method,
      device: deviceId,
      decision: 'DENY',
      reason: `Password salah untuk user '${username}'`,
      ip: req.ip
    });
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }

  // Verifikasi Konteks: Apakah device terdaftar untuk user ini?
  const device = db.prepare('SELECT * FROM devices WHERE user_id = ? AND device_id = ?').get(user.id, deviceId);
  if (!device) {
    logAudit({
      subject: username,
      endpoint,
      method,
      device: deviceId,
      decision: 'DENY',
      reason: `Device '${deviceId}' tidak terdaftar untuk user '${username}'`,
      ip: req.ip
    });
    return res.status(403).json({
      error: `Device '${deviceId}' tidak terdaftar untuk akun '${username}'`,
      code: 'DEVICE_UNREGISTERED'
    });
  }

  // 1. Buat Access Token JWT (berlaku 10 menit)
  const accessToken = jwt.sign(
    {
      sub: user.id,
      userId: user.id,
      username: user.username,
      role: user.role,
      identifier: user.identifier,
      nama: user.nama
    },
    config.jwt.secret,
    { expiresIn: config.jwt.accessExpiresIn }
  );

  // 2. Buat Refresh Token (berlaku 1 hari, disimpan di DB)
  const refreshToken = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO refresh_tokens (token, user_id, revoked, expires_at)
    VALUES (?, ?, 0, ?)
  `).run(refreshToken, user.id, expiresAt);

  logAudit({
    subject: username,
    endpoint,
    method,
    device: deviceId,
    decision: 'ALLOW',
    reason: `Login berhasil dari device terdaftar '${deviceId}' (${device.device_name || 'Device'})`,
    ip: req.ip
  });

  return res.json({
    status: 'success',
    message: 'Login berhasil',
    accessToken,
    refreshToken,
    expiresIn: config.jwt.accessExpiresIn,
    user: {
      id: user.id,
      username: user.username,
      nama: user.nama,
      role: user.role,
      identifier: user.identifier,
      device: {
        id: device.device_id,
        name: device.device_name
      }
    }
  });
});

/**
 * POST /auth/refresh
 * Menukar refresh token valid dan belum dicabut dengan access token baru
 */
app.post('/auth/refresh', (req, res) => {
  const { refreshToken } = req.body;
  const endpoint = '/auth/refresh';
  const method = 'POST';
  const deviceId = req.headers['x-device-id'] || '-';

  if (!refreshToken) {
    logAudit({
      subject: 'anonymous',
      endpoint,
      method,
      device: deviceId,
      decision: 'DENY',
      reason: 'Payload refreshToken wajib disertakan',
      ip: req.ip
    });
    return res.status(400).json({ error: 'Payload refreshToken wajib disertakan' });
  }

  const tokenRecord = db.prepare(`
    SELECT rt.*, u.username, u.role, u.identifier, u.nama
    FROM refresh_tokens rt
    JOIN users u ON rt.user_id = u.id
    WHERE rt.token = ?
  `).get(refreshToken);

  if (!tokenRecord) {
    logAudit({
      subject: 'anonymous',
      endpoint,
      method,
      device: deviceId,
      decision: 'DENY',
      reason: 'Refresh token tidak ditemukan di database',
      ip: req.ip
    });
    return res.status(401).json({ error: 'Refresh token tidak valid' });
  }

  if (tokenRecord.revoked === 1) {
    logAudit({
      subject: tokenRecord.username,
      endpoint,
      method,
      device: deviceId,
      decision: 'DENY',
      reason: 'Refresh token telah dicabut (revoked)',
      ip: req.ip
    });
    return res.status(401).json({ error: 'Refresh token telah dicabut' });
  }

  if (new Date(tokenRecord.expires_at) < new Date()) {
    logAudit({
      subject: tokenRecord.username,
      endpoint,
      method,
      device: deviceId,
      decision: 'DENY',
      reason: 'Refresh token telah kedaluwarsa',
      ip: req.ip
    });
    return res.status(401).json({ error: 'Refresh token telah kedaluwarsa' });
  }

  // Buat Access Token baru
  const newAccessToken = jwt.sign(
    {
      sub: tokenRecord.user_id,
      userId: tokenRecord.user_id,
      username: tokenRecord.username,
      role: tokenRecord.role,
      identifier: tokenRecord.identifier,
      nama: tokenRecord.nama
    },
    config.jwt.secret,
    { expiresIn: config.jwt.accessExpiresIn }
  );

  logAudit({
    subject: tokenRecord.username,
    endpoint,
    method,
    device: deviceId,
    decision: 'ALLOW',
    reason: 'Refresh access token berhasil',
    ip: req.ip
  });

  return res.json({
    status: 'success',
    accessToken: newAccessToken,
    expiresIn: config.jwt.accessExpiresIn
  });
});

/**
 * POST /auth/logout
 * Mencabut refresh token agar tidak dapat digunakan lagi
 */
app.post('/auth/logout', (req, res) => {
  const { refreshToken } = req.body;
  const endpoint = '/auth/logout';
  const method = 'POST';
  const deviceId = req.headers['x-device-id'] || '-';

  if (!refreshToken) {
    return res.status(400).json({ error: 'Payload refreshToken wajib disertakan untuk logout' });
  }

  const tokenRecord = db.prepare('SELECT rt.*, u.username FROM refresh_tokens rt JOIN users u ON rt.user_id = u.id WHERE rt.token = ?').get(refreshToken);
  const subject = tokenRecord ? tokenRecord.username : 'anonymous';

  db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?').run(refreshToken);

  logAudit({
    subject,
    endpoint,
    method,
    device: deviceId,
    decision: 'ALLOW',
    reason: 'Logout berhasil, refresh token dicabut (revoked)',
    ip: req.ip
  });

  return res.json({
    status: 'success',
    message: 'Logout berhasil, refresh token telah dicabut'
  });
});

/**
 * POST /auth/service
 * Menerbitkan service token untuk Service Nilai menggunakan client ID & secret
 * Token berlaku 5 menit dengan role: service
 */
app.post('/auth/service', (req, res) => {
  const { clientId, clientSecret } = req.body;
  const endpoint = '/auth/service';
  const method = 'POST';

  if (!clientId || !clientSecret) {
    logAudit({
      subject: clientId || 'anonymous_service',
      endpoint,
      method,
      device: '-',
      decision: 'DENY',
      reason: 'clientId dan clientSecret wajib disertakan',
      ip: req.ip
    });
    return res.status(400).json({ error: 'clientId dan clientSecret wajib disertakan' });
  }

  const client = db.prepare('SELECT * FROM service_clients WHERE client_id = ? AND client_secret = ?').get(clientId, clientSecret);
  if (!client) {
    logAudit({
      subject: clientId,
      endpoint,
      method,
      device: '-',
      decision: 'DENY',
      reason: `Client credentials tidak valid untuk clientId '${clientId}'`,
      ip: req.ip
    });
    return res.status(401).json({ error: 'Client credentials tidak valid' });
  }

  const serviceToken = jwt.sign(
    {
      sub: client.client_id,
      role: 'service',
      serviceName: client.service_name
    },
    config.jwt.secret,
    { expiresIn: config.jwt.serviceExpiresIn }
  );

  logAudit({
    subject: client.client_id,
    endpoint,
    method,
    device: '-',
    decision: 'ALLOW',
    reason: `Penerbitan token service berhasil untuk '${client.service_name}' (role: service, masa berlaku: 5 menit)`,
    ip: req.ip
  });

  return res.json({
    status: 'success',
    token: serviceToken,
    tokenType: 'Bearer',
    role: 'service',
    expiresIn: config.jwt.serviceExpiresIn
  });
});

// Endpoint untuk melihat Audit Log (Khusus Admin atau untuk evaluasi praktikum)
app.get('/audit-logs', (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 50;
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?').all(limit);
  return res.json({
    status: 'success',
    count: logs.length,
    logs
  });
});

// Status Gateway
app.get('/', (req, res) => {
  res.json({
    gateway: 'API Gateway Policy Enforcement Point (PEP)',
    architecture: 'NIST SP 800-207 Zero Trust Architecture',
    ports: {
      gateway: config.gateway.port,
      serviceNilai: config.services.nilai.port,
      serviceTranskrip: config.services.transkrip.port
    },
    status: 'online'
  });
});

// =========================================================================
// 2. PEP MIDDLEWARE (Policy Enforcement Point)
// =========================================================================

function pepMiddleware(req, res, next) {
  const decision = policyEngine.evaluate(req);
  const subject = decision.subject || 'anonymous';
  const device = req.headers['x-device-id'] || '-';

  if (!decision.allowed) {
    logAudit({
      subject,
      endpoint: req.originalUrl,
      method: req.method,
      device,
      decision: 'DENY',
      reason: decision.reason,
      ip: req.ip
    });

    const statusCode = (decision.code === 'TOKEN_MISSING' || decision.code === 'TOKEN_INVALID') ? 401 : 403;
    return res.status(statusCode).json({
      error: 'Access Denied by Policy Enforcement Point (PEP)',
      code: decision.code || 'ACCESS_DENIED',
      reason: decision.reason
    });
  }

  // Jika ALLOW, catat audit log lalu teruskan ke target service
  logAudit({
    subject,
    endpoint: req.originalUrl,
    method: req.method,
    device,
    decision: 'ALLOW',
    reason: decision.reason,
    ip: req.ip
  });

  next();
}

// =========================================================================
// 3. REVERSE PROXY DENGAN INJEKSI GATEWAY SECRET
// =========================================================================

// Proxy ke Service Nilai (port 3001)
const nilaiProxy = createProxyMiddleware({
  target: config.services.nilai.url,
  changeOrigin: true,
  pathRewrite: (path, req) => req.originalUrl,
  on: {
    proxyReq: (proxyReq, req) => {
      // Injeksi Gateway Secret saat meneruskan request
      proxyReq.setHeader('x-gateway-secret', config.gateway.secret);
      fixRequestBody(proxyReq, req);
    },
    error: (err, req, res) => {
      console.error('[PROXY ERROR Nilai]', err.message);
      res.status(502).json({ error: 'Service Nilai tidak dapat dihubungi (Bad Gateway)', details: err.message });
    }
  }
});

// Proxy ke Service Transkrip (port 3002)
const transkripProxy = createProxyMiddleware({
  target: config.services.transkrip.url,
  changeOrigin: true,
  pathRewrite: (path, req) => req.originalUrl,
  on: {
    proxyReq: (proxyReq, req) => {
      // Injeksi Gateway Secret saat meneruskan request
      proxyReq.setHeader('x-gateway-secret', config.gateway.secret);
      fixRequestBody(proxyReq, req);
    },
    error: (err, req, res) => {
      console.error('[PROXY ERROR Transkrip]', err.message);
      res.status(502).json({ error: 'Service Transkrip tidak dapat dihubungi (Bad Gateway)', details: err.message });
    }
  }
});

// Pasang PEP Middleware & Proxy ke rute target
app.use('/nilai', pepMiddleware, nilaiProxy);
app.use('/kelas', pepMiddleware, nilaiProxy);
app.use('/transkrip', pepMiddleware, transkripProxy);

function startServer(port = config.gateway.port) {
  return app.listen(port, () => {
    console.log(`[API GATEWAY (PEP)] Berjalan di port ${port}`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };
