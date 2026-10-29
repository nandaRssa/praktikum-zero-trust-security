require('dotenv').config();
const path = require('path');

module.exports = {
  gateway: {
    port: parseInt(process.env.PORT_GATEWAY, 10) || 3000,
    secret: process.env.GATEWAY_SECRET || 'zero-trust-gateway-shared-secret-key-unsil-2024'
  },
  services: {
    nilai: {
      port: parseInt(process.env.PORT_NILAI, 10) || 3001,
      url: `http://localhost:${parseInt(process.env.PORT_NILAI, 10) || 3001}`
    },
    transkrip: {
      port: parseInt(process.env.PORT_TRANSKRIP, 10) || 3002,
      url: `http://localhost:${parseInt(process.env.PORT_TRANSKRIP, 10) || 3002}`
    }
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'zero-trust-jwt-secure-signing-key-unsil-2024',
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN || '10m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '1d',
    serviceExpiresIn: process.env.JWT_SERVICE_EXPIRES_IN || '5m'
  },
  accessHours: {
    start: parseInt(process.env.ACCESS_HOURS_START, 10) || 7,
    end: parseInt(process.env.ACCESS_HOURS_END, 10) || 21
  },
  database: {
    path: path.resolve(__dirname, '../../', process.env.DATABASE_PATH || 'database.sqlite')
  },
  audit: {
    logFile: path.resolve(__dirname, '../../', process.env.AUDIT_LOG_FILE || 'audit.log')
  }
};
