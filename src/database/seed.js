const bcrypt = require('bcryptjs');
const { getDatabase } = require('./connection');

function seedDatabase(db = getDatabase()) {
  console.log('[SEED] Memulai proses seeding database...');

  // Reset tabel agar bersih saat seeding ulang
  db.pragma('foreign_keys = OFF');
  db.exec(`
    DELETE FROM audit_logs;
    DELETE FROM transkrip;
    DELETE FROM nilai;
    DELETE FROM kelas;
    DELETE FROM refresh_tokens;
    DELETE FROM service_clients;
    DELETE FROM devices;
    DELETE FROM users;
    DELETE FROM sqlite_sequence;
  `);
  db.pragma('foreign_keys = ON');

  const passwordHash = bcrypt.hashSync('password123', 10);

  // 1. Seed Users (1 Admin, 2 Dosen, 3 Mahasiswa)
  const insertUser = db.prepare(`
    INSERT INTO users (username, password, role, identifier, nama)
    VALUES (?, ?, ?, ?, ?)
  `);

  const adminResult = insertUser.run('admin1', passwordHash, 'admin', 'ADM001', 'Administrator Akademik');
  const dosen1Result = insertUser.run('dosen_fahri', passwordHash, 'dosen', '0401018001', 'Dr. Fahri Hidayat, M.Kom.');
  const dosen2Result = insertUser.run('dosen_siti', passwordHash, 'dosen', '0402028202', 'Dr. Siti Aminah, M.T.');
  const mhs1Result = insertUser.run('mhs_andi', passwordHash, 'mahasiswa', '227006001', 'Andi Pratama');
  const mhs2Result = insertUser.run('mhs_arhan', passwordHash, 'mahasiswa', '227006002', 'Arhan Maulana');
  const mhs3Result = insertUser.run('mhs_yuli', passwordHash, 'mahasiswa', '227006003', 'Yuli Rahmawati');

  const adminId = adminResult.lastInsertRowid;
  const dosenFahriId = dosen1Result.lastInsertRowid;
  const dosenSitiId = dosen2Result.lastInsertRowid;
  const mhsAndiId = mhs1Result.lastInsertRowid;
  const mhsArhanId = mhs2Result.lastInsertRowid;
  const mhsYuliId = mhs3Result.lastInsertRowid;

  // 2. Seed Registered Devices (Setiap user memiliki 1 device terdaftar)
  const insertDevice = db.prepare(`
    INSERT INTO devices (user_id, device_id, device_name)
    VALUES (?, ?, ?)
  `);

  insertDevice.run(adminId, 'DEV-ADMIN-01', 'Laptop Admin ThinkPad');
  insertDevice.run(dosenFahriId, 'DEV-DOSEN-01', 'MacBook Pro Dosen Fahri');
  insertDevice.run(dosenSitiId, 'DEV-DOSEN-02', 'Dell XPS Dosen Siti');
  insertDevice.run(mhsAndiId, 'DEV-MHS-01', 'Asus ROG Andi');
  insertDevice.run(mhsArhanId, 'DEV-MHS-02', 'MacBook Air Arhan');
  insertDevice.run(mhsYuliId, 'DEV-MHS-03', 'HP Pavilion Yuli');

  // 3. Seed Service Client (Service Nilai)
  const insertClient = db.prepare(`
    INSERT INTO service_clients (client_id, client_secret, service_name)
    VALUES (?, ?, ?)
  `);
  insertClient.run('service-nilai', 'secret-service-nilai-xyz', 'Service Nilai (Internal)');

  // 4. Seed Kelas (2 kelas yang diampu dosen berbeda)
  const insertKelas = db.prepare(`
    INSERT INTO kelas (kode_mk, nama_mk, sks, dosen_id, is_final)
    VALUES (?, ?, ?, ?, ?)
  `);

  const kelas1Result = insertKelas.run('IF301', 'Keamanan Informasi', 3, dosenFahriId, 0); // Diampu Dosen Fahri
  const kelas2Result = insertKelas.run('IF302', 'Kriptografi', 3, dosenSitiId, 0);          // Diampu Dosen Siti

  const kelas1Id = kelas1Result.lastInsertRowid;
  const kelas2Id = kelas2Result.lastInsertRowid;

  // 5. Seed Nilai (Data nilai mahasiswa di kelas)
  const insertNilai = db.prepare(`
    INSERT INTO nilai (kelas_id, mahasiswa_id, nilai_angka, nilai_huruf)
    VALUES (?, ?, ?, ?)
  `);

  // Nilai kelas Keamanan Informasi (Dosen Fahri): Andi & Arhan
  insertNilai.run(kelas1Id, mhsAndiId, 85.5, 'A');
  insertNilai.run(kelas1Id, mhsArhanId, 75.0, 'B');

  // Nilai kelas Kriptografi (Dosen Siti): Arhan & Yuli
  insertNilai.run(kelas2Id, mhsArhanId, 88.0, 'A');
  insertNilai.run(kelas2Id, mhsYuliId, 82.0, 'B');

  console.log('[SEED] Seeding selesai dengan sukses!');
  console.log('       - 1 Admin, 2 Dosen, 3 Mahasiswa dibuat.');
  console.log('       - 6 Device terdaftar.');
  console.log('       - 2 Kelas & 4 Record Nilai dibuat.');
  console.log('       - 1 Service Client (service-nilai) didaftarkan.');
}

module.exports = {
  seedDatabase
};
