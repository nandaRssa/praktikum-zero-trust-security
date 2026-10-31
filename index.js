const { getDatabase } = require('./src/database/connection');
const { seedDatabase } = require('./src/database/seed');
const gateway = require('./src/gateway');
const serviceNilai = require('./src/services/nilai');
const serviceTranskrip = require('./src/services/transkrip');
const config = require('./src/config');

console.log('='.repeat(60));
console.log('  SISTEM NILAI & TRANSKRIP - ZERO TRUST ARCHITECTURE');
console.log('='.repeat(60));

// Pastikan database siap dan terisi seed
const db = getDatabase();
const usersCount = db.prepare('SELECT count(*) as count FROM users').get().count;
if (usersCount === 0) {
  console.log('[INIT] Database kosong, menjalankan seed otomatis...');
  seedDatabase(db);
}

// 1. Jalankan Service Nilai (port 3001)
const srvNilai = serviceNilai.startServer(config.services.nilai.port);

// 2. Jalankan Service Transkrip (port 3002)
const srvTranskrip = serviceTranskrip.startServer(config.services.transkrip.port);

// 3. Jalankan API Gateway PEP (port 3000)
const srvGateway = gateway.startServer(config.gateway.port);

console.log('='.repeat(60));
console.log(`[STATUS] Seluruh komponen Zero Trust berjalan dengan baik:`);
console.log(`  1. API Gateway (PEP)      : http://localhost:${config.gateway.port}`);
console.log(`  2. Service Nilai          : http://localhost:${config.services.nilai.port} (Direct access diblokir)`);
console.log(`  3. Service Transkrip      : http://localhost:${config.services.transkrip.port} (Direct access diblokir)`);
console.log(`  4. Audit Log File         : ${config.audit.logFile}`);
console.log('='.repeat(60));

// Handle graceful shutdown
function shutdown() {
  console.log('\n[SHUTDOWN] Menghentikan seluruh service...');
  srvGateway.close();
  srvNilai.close();
  srvTranskrip.close();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
