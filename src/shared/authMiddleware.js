const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Middleware Zero Trust untuk Resource Services (Service Nilai & Service Transkrip):
 * 1. Verifikasi Gateway Secret (Mencegah direct access / bypass API Gateway)
 * 2. Verifikasi Ulang Token JWT (Prinsip Assume Breach: Never Trust, Always Verify)
 */
function verifyServiceAccess(req, res, next) {
  // 1. Verifikasi Gateway Secret
  const gatewaySecret = req.headers['x-gateway-secret'];
  if (!gatewaySecret || gatewaySecret !== config.gateway.secret) {
    return res.status(403).json({
      error: 'Forbidden: Direct service access denied. Request must pass through API Gateway (PEP).',
      code: 'DIRECT_ACCESS_BLOCKED'
    });
  }

  // 2. Verifikasi Ulang Token JWT
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized: Missing or malformed Bearer token.',
      code: 'TOKEN_MISSING'
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.jwt.secret);
    req.user = decoded; // Berisi sub, role, identifier, dll.
    next();
  } catch (err) {
    return res.status(401).json({
      error: 'Unauthorized: Invalid or expired token.',
      message: err.message,
      code: 'TOKEN_INVALID'
    });
  }
}

module.exports = {
  verifyServiceAccess
};
