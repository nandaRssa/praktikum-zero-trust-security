const http = require('http');
const { getDatabase } = require('../src/database/connection');
const { seedDatabase } = require('../src/database/seed');
const gateway = require('../src/gateway');
const serviceNilai = require('../src/services/nilai');
const serviceTranskrip = require('../src/services/transkrip');
const config = require('../src/config');

// ANSI Color helper
const green = (t) => `\x1b[32m${t}\x1b[0m`;
const red = (t) => `\x1b[31m${t}\x1b[0m`;
const cyan = (t) => `\x1b[36m${t}\x1b[0m`;
const yellow = (t) => `\x1b[33m${t}\x1b[0m`;
const bold = (t) => `\x1b[1m${t}\x1b[0m`;

let passedCount = 0;
let failedCount = 0;

function assert(condition, testName, details = '') {
  if (condition) {
    passedCount++;
    console.log(`  ${green('✔ PASS')} - ${testName}`);
  } else {
    failedCount++;
    console.log(`  ${red('✖ FAIL')} - ${testName} ${details ? `(${details})` : ''}`);
  }
}

async function runTests() {
  console.log(bold('\n============================================================='));
  console.log(bold('  MENJALANKAN AUTOMATED TEST SUITE: ZERO TRUST SECURITY'));
  console.log(bold('=============================================================\n'));

  // 1. Inisialisasi DB & Server
  const db = getDatabase();
  seedDatabase(db);

  const srvNilai = serviceNilai.startServer(config.services.nilai.port);
  const srvTranskrip = serviceTranskrip.startServer(config.services.transkrip.port);
  const srvGateway = gateway.startServer(config.gateway.port);

  // Tunggu sejenak hingga semua listener siap
  await new Promise(r => setTimeout(r, 800));

  const gwUrl = `http://localhost:${config.gateway.port}`;
  const nilaiUrl = `http://localhost:${config.services.nilai.port}`;
  const transkripUrl = `http://localhost:${config.services.transkrip.port}`;

  try {
    // -------------------------------------------------------------
    // PENGUJIAN 1: VERIFIKASI KEAMANAN SERVICE DIRECT ACCESS (PEP BYPASS)
    // -------------------------------------------------------------
    console.log(cyan('\n--- 1. UJI PERLINDUNGAN DIRECT ACCESS KE RESOURCE SERVICE ---'));

    // A. Akses langsung ke Service Nilai tanpa X-Gateway-Secret -> HARUS DITOLAK (403)
    const directNilai = await fetch(`${nilaiUrl}/nilai`, { method: 'GET' });
    assert(directNilai.status === 403, 'Akses langsung ke Service Nilai tanpa X-Gateway-Secret ditolak (HTTP 403)');

    // B. Akses langsung ke Service Transkrip tanpa X-Gateway-Secret -> HARUS DITOLAK (403)
    const directTranskrip = await fetch(`${transkripUrl}/transkrip/227006001`, { method: 'GET' });
    assert(directTranskrip.status === 403, 'Akses langsung ke Service Transkrip tanpa X-Gateway-Secret ditolak (HTTP 403)');

    // C. Akses ke Service Nilai membawa X-Gateway-Secret tapi tanpa token valid (Assume Breach) -> HARUS DITOLAK (401)
    const fakeSecretNilai = await fetch(`${nilaiUrl}/nilai`, {
      method: 'GET',
      headers: { 'X-Gateway-Secret': config.gateway.secret }
    });
    assert(fakeSecretNilai.status === 401, 'Service Nilai menolak request dengan secret tapi tanpa token valid (Assume Breach)');

    // -------------------------------------------------------------
    // PENGUJIAN 2: AUTENTIKASI, TOKEN, & DEVICE CONTEXT
    // -------------------------------------------------------------
    console.log(cyan('\n--- 2. UJI AUTENTIKASI, DEVICE TERDAFTAR, & TOKEN LIFECYCLE ---'));

    // A. Login tanpa header X-Device-ID -> HARUS DITOLAK (400)
    const loginNoDev = await fetch(`${gwUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'mhs_andi', password: 'password123' })
    });
    assert(loginNoDev.status === 400, 'Login tanpa header X-Device-ID ditolak (HTTP 400)');

    // B. Login dengan device tidak terdaftar -> HARUS DITOLAK (403)
    const loginFakeDev = await fetch(`${gwUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-HACKER-DEVICE'
      },
      body: JSON.stringify({ username: 'mhs_andi', password: 'password123' })
    });
    assert(loginFakeDev.status === 403, 'Login dengan device tidak terdaftar ditolak (HTTP 403)');

    // C. Login Mahasiswa Andi dengan device terdaftar -> BERHASIL (200)
    const loginAndi = await fetch(`${gwUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-MHS-01'
      },
      body: JSON.stringify({ username: 'mhs_andi', password: 'password123' })
    });
    const andiData = await loginAndi.json();
    assert(loginAndi.status === 200 && andiData.accessToken, 'Login Mahasiswa Andi dengan device terdaftar berhasil (HTTP 200)');
    const andiToken = andiData.accessToken;
    const andiRefreshToken = andiData.refreshToken;

    // D. Login Dosen Fahri dengan device terdaftar -> BERHASIL
    const loginFahri = await fetch(`${gwUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-DOSEN-01'
      },
      body: JSON.stringify({ username: 'dosen_fahri', password: 'password123' })
    });
    const fahriData = await loginFahri.json();
    assert(loginFahri.status === 200 && fahriData.accessToken, 'Login Dosen Fahri dengan device terdaftar berhasil');
    const fahriToken = fahriData.accessToken;

    // E. Login Dosen Siti dengan device terdaftar -> BERHASIL
    const loginSiti = await fetch(`${gwUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-DOSEN-02'
      },
      body: JSON.stringify({ username: 'dosen_siti', password: 'password123' })
    });
    const sitiData = await loginSiti.json();
    assert(loginSiti.status === 200 && sitiData.accessToken, 'Login Dosen Siti dengan device terdaftar berhasil');
    const sitiToken = sitiData.accessToken;

    // F. Login Admin dengan device terdaftar -> BERHASIL
    const loginAdmin = await fetch(`${gwUrl}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-ID': 'DEV-ADMIN-01'
      },
      body: JSON.stringify({ username: 'admin1', password: 'password123' })
    });
    const adminData = await loginAdmin.json();
    assert(loginAdmin.status === 200 && adminData.accessToken, 'Login Admin dengan device terdaftar berhasil');
    const adminToken = adminData.accessToken;

    // G. Refresh Token: Tukar refresh token dengan access token baru -> BERHASIL
    const refreshRes = await fetch(`${gwUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: andiRefreshToken })
    });
    const refreshData = await refreshRes.json();
    assert(refreshRes.status === 200 && refreshData.accessToken, 'Refresh token berhasil menerbitkan access token baru');

    // H. Logout: Mencabut refresh token -> BERHASIL
    const logoutRes = await fetch(`${gwUrl}/auth/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: andiRefreshToken })
    });
    assert(logoutRes.status === 200, 'Logout berhasil dan mencabut refresh token');

    // I. Gunakan kembali refresh token yang telah dicabut -> HARUS DITOLAK (401)
    const reuseRevoked = await fetch(`${gwUrl}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: andiRefreshToken })
    });
    assert(reuseRevoked.status === 401, 'Refresh token yang telah dicabut ditolak (HTTP 401)');

    // J. Token Service: Service Nilai meminta token service dengan client ID & secret -> BERHASIL
    const serviceTokenRes = await fetch(`${gwUrl}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientId: 'service-nilai', clientSecret: 'secret-service-nilai-xyz' })
    });
    const serviceTokenData = await serviceTokenRes.json();
    assert(serviceTokenRes.status === 200 && serviceTokenData.role === 'service', 'Service token berhasil diterbitkan dengan role: service');
    const serviceToken = serviceTokenData.token;

    // -------------------------------------------------------------
    // PENGUJIAN 3: KEBIJAKAN AKSES DATA NILAI (GET /nilai, PUT /nilai/:id)
    // -------------------------------------------------------------
    console.log(cyan('\n--- 3. UJI KEBIJAKAN AKSES NILAI (LEAST PRIVILEGE & OWNERSHIP) ---'));

    // Ambil data referensi dari database
    const kelasFahri = db.prepare("SELECT * FROM kelas WHERE kode_mk = 'IF301'").get();
    const kelasSiti = db.prepare("SELECT * FROM kelas WHERE kode_mk = 'IF302'").get();
    const nilaiFahri = db.prepare("SELECT * FROM nilai WHERE kelas_id = ?").get(kelasFahri.id);
    const nilaiSiti = db.prepare("SELECT * FROM nilai WHERE kelas_id = ?").get(kelasSiti.id);
    const mhsAndi = db.prepare("SELECT * FROM users WHERE username = 'mhs_andi'").get();
    const mhsArhan = db.prepare("SELECT * FROM users WHERE username = 'mhs_arhan'").get();

    // A. Mahasiswa Andi akses GET /nilai dari device terdaftar -> Hanya melihat nilai miliknya
    const andiNilaiRes = await fetch(`${gwUrl}/nilai`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${andiToken}`,
        'X-Device-ID': 'DEV-MHS-01'
      }
    });
    const andiNilaiData = await andiNilaiRes.json();
    assert(
      andiNilaiRes.status === 200 && andiNilaiData.data.length === 1 && andiNilaiData.data[0].kode_mk === 'IF301',
      'Mahasiswa Andi hanya melihat nilai mata kuliah miliknya sendiri'
    );

    // B. Dosen Fahri akses GET /nilai dari device terdaftar -> Hanya melihat kelas yang diampunya (IF301)
    const fahriNilaiRes = await fetch(`${gwUrl}/nilai`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01'
      }
    });
    const fahriNilaiData = await fahriNilaiRes.json();
    const allFahriClasses = fahriNilaiData.data && fahriNilaiData.data.every(d => d.kode_mk === 'IF301');
    assert(fahriNilaiRes.status === 200 && allFahriClasses, 'Dosen Fahri hanya melihat kelas yang diampunya (IF301)');

    // C. Mahasiswa mencoba mengubah nilai (PUT /nilai/:id) -> HARUS DITOLAK (403)
    const mhsEditNilai = await fetch(`${gwUrl}/nilai/${nilaiFahri.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${andiToken}`,
        'X-Device-ID': 'DEV-MHS-01'
      },
      body: JSON.stringify({ nilai_angka: 100 })
    });
    assert(mhsEditNilai.status === 403, 'Mahasiswa dilarang mengubah nilai (HTTP 403 Role Forbidden)');

    // D. Dosen Fahri mencoba mengubah nilai kelas Dosen Siti -> HARUS DITOLAK (403 Not Class Owner)
    const fahriEditSiti = await fetch(`${gwUrl}/nilai/${nilaiSiti.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01'
      },
      body: JSON.stringify({ nilai_angka: 95 })
    });
    assert(fahriEditSiti.status === 403, 'Dosen dilarang mengubah nilai kelas yang bukan diampunya (HTTP 403 Not Class Owner)');

    // E. Dosen Fahri mengubah nilai di luar jam akses (simulasi jam 22.00) -> HARUS DITOLAK (403)
    const fahriEditOffHours = await fetch(`${gwUrl}/nilai/${nilaiFahri.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01',
        'X-Simulate-Hour': '22' // Jam 22.00 di luar 07.00-21.00
      },
      body: JSON.stringify({ nilai_angka: 90 })
    });
    assert(fahriEditOffHours.status === 403, 'Perubahan nilai di luar jam akses (07.00-21.00) ditolak (HTTP 403 Outside Hours)');

    // F. Dosen Fahri mengubah nilai dalam jam akses (simulasi jam 10.00) -> BERHASIL (200)
    const fahriEditValid = await fetch(`${gwUrl}/nilai/${nilaiFahri.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01',
        'X-Simulate-Hour': '10' // Jam 10.00 dalam jam akses
      },
      body: JSON.stringify({ nilai_angka: 92.0 })
    });
    const editData = await fahriEditValid.json();
    assert(fahriEditValid.status === 200 && editData.data.nilai_angka === 92.0, 'Dosen Fahri berhasil mengubah nilai dalam jam akses');

    // -------------------------------------------------------------
    // PENGUJIAN 4: FINALISASI KELAS & PANGGILAN ANTAR-SERVICE KE TRANSKRIP
    // -------------------------------------------------------------
    console.log(cyan('\n--- 4. UJI FINALISASI KELAS & SINKRONISASI TRANSKRIP (INTER-SERVICE) ---'));

    // A. Dosen Siti mencoba memfinalisasi kelas Dosen Fahri -> HARUS DITOLAK (403)
    const sitiFinalizeFahri = await fetch(`${gwUrl}/kelas/${kelasFahri.id}/finalisasi`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${sitiToken}`,
        'X-Device-ID': 'DEV-DOSEN-02',
        'X-Simulate-Hour': '11'
      }
    });
    assert(sitiFinalizeFahri.status === 403, 'Dosen Siti dilarang memfinalisasi kelas yang diampu Dosen Fahri');

    // B. Dosen Fahri finalisasi kelas IF301 dalam jam akses -> BERHASIL & Antar-service sinkron ke Transkrip
    const finalizeRes = await fetch(`${gwUrl}/kelas/${kelasFahri.id}/finalisasi`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01',
        'X-Simulate-Hour': '11'
      }
    });
    const finalizeData = await finalizeRes.json();
    assert(
      finalizeRes.status === 200 && finalizeData.syncResult && finalizeData.syncResult.syncedCount > 0,
      'Finalisasi kelas berhasil dan otomatis sinkron ke Service Transkrip via Gateway (Inter-service)'
    );

    // C. Coba ubah nilai pada kelas yang sudah difinalisasi -> HARUS DITOLAK (403)
    const editAfterFinal = await fetch(`${gwUrl}/nilai/${nilaiFahri.id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01',
        'X-Simulate-Hour': '12'
      },
      body: JSON.stringify({ nilai_angka: 95 })
    });
    assert(editAfterFinal.status === 403, 'Nilai pada kelas yang sudah difinalisasi dilarang diubah (HTTP 403)');

    // D. Finalisasi ulang kelas yang sudah final -> HARUS DITOLAK (403)
    const reFinalize = await fetch(`${gwUrl}/kelas/${kelasFahri.id}/finalisasi`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01',
        'X-Simulate-Hour': '12'
      }
    });
    assert(reFinalize.status === 403, 'Finalisasi ulang kelas yang sudah final ditolak');

    // -------------------------------------------------------------
    // PENGUJIAN 5: KEBIJAKAN AKSES TRANSKRIP & ROLE RESTRICTION
    // -------------------------------------------------------------
    console.log(cyan('\n--- 5. UJI KEBIJAKAN AKSES TRANSKRIP & PROTEKSI SINKRONISASI ---'));

    // A. Mahasiswa Andi melihat transkrip miliknya sendiri (NIM: 227006001) -> BERHASIL
    const andiTranskripRes = await fetch(`${gwUrl}/transkrip/227006001`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${andiToken}`,
        'X-Device-ID': 'DEV-MHS-01'
      }
    });
    const andiTranskripData = await andiTranskripRes.json();
    assert(
      andiTranskripRes.status === 200 && andiTranskripData.transkrip.length > 0,
      'Mahasiswa Andi berhasil melihat transkrip miliknya sendiri (terisi otomatis dari sinkronisasi)'
    );

    // B. Mahasiswa Andi mencoba mengintip transkrip Mahasiswa Arhan (NIM: 227006002) -> HARUS DITOLAK (403)
    const andiPeekArhan = await fetch(`${gwUrl}/transkrip/227006002`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${andiToken}`,
        'X-Device-ID': 'DEV-MHS-01'
      }
    });
    assert(andiPeekArhan.status === 403, 'Mahasiswa dilarang melihat transkrip mahasiswa lain (NIM Mismatch HTTP 403)');

    // C. Admin melihat transkrip Andi dan Arhan -> BERHASIL SEMUA
    const adminViewAndi = await fetch(`${gwUrl}/transkrip/227006001`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'X-Device-ID': 'DEV-ADMIN-01'
      }
    });
    const adminViewArhan = await fetch(`${gwUrl}/transkrip/227006002`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'X-Device-ID': 'DEV-ADMIN-01'
      }
    });
    assert(adminViewAndi.status === 200 && adminViewArhan.status === 200, 'Admin berhak melihat transkrip seluruh mahasiswa');

    // D. User biasa (Dosen Fahri) mencoba memanggil POST /transkrip/sinkron -> HARUS DITOLAK (403)
    const userCallSync = await fetch(`${gwUrl}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${fahriToken}`,
        'X-Device-ID': 'DEV-DOSEN-01'
      },
      body: JSON.stringify({ items: [] })
    });
    assert(userCallSync.status === 403, 'User (Dosen/Mahasiswa/Admin) dilarang memanggil /transkrip/sinkron (Hanya Service Token)');

    // E. Token Service memanggil POST /transkrip/sinkron -> BERHASIL (200)
    const serviceCallSync = await fetch(`${gwUrl}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`
      },
      body: JSON.stringify({
        items: [
          {
            mahasiswa_id: mhsArhan.id,
            nim: mhsArhan.identifier,
            kode_mk: 'IF999',
            nama_mk: 'Praktikum Zero Trust',
            sks: 3,
            nilai_huruf: 'A'
          }
        ]
      })
    });
    assert(serviceCallSync.status === 200, 'Token Service internal diizinkan memanggil /transkrip/sinkron');

    // -------------------------------------------------------------
    // PENGUJIAN 6: AUDIT LOG (DATA SOURCE VERIFICATION)
    // -------------------------------------------------------------
    console.log(cyan('\n--- 6. UJI AUDIT LOG (DECISION, SUBJECT, DEVICE, REASON) ---'));

    const auditCount = db.prepare('SELECT count(*) as count FROM audit_logs').get().count;
    const allowCount = db.prepare("SELECT count(*) as count FROM audit_logs WHERE decision = 'ALLOW'").get().count;
    const denyCount = db.prepare("SELECT count(*) as count FROM audit_logs WHERE decision = 'DENY'").get().count;

    assert(auditCount > 15, `Audit log mencatat seluruh request (${auditCount} log entri tercatat)`);
    assert(allowCount > 0 && denyCount > 0, `Audit log memisahkan keputusan ALLOW (${allowCount}) dan DENY (${denyCount}) dengan alasan akurat`);

  } catch (err) {
    console.error(red('Terjadi kesalahan fatal saat pengujian:'), err);
    failedCount++;
  } finally {
    // Tutup server
    srvGateway.close();
    srvNilai.close();
    srvTranskrip.close();
  }

  // Tampilkan Rangkuman
  console.log(bold('  RANGKUMAN HASIL PENGUJIAN:'));
  console.log(`  Total Pengujian : ${passedCount + failedCount}`);
  console.log(`  ${green('LULUS (PASS)')}   : ${passedCount}`);
  console.log(`  ${red('GAGAL (FAIL)')}   : ${failedCount}`);
  if (failedCount === 0) {
    console.log(green(bold('\n  SELURUH PRINSIP ZERO TRUST & SKENARIO BERHASIL\n')));
  } else {
    console.log(red(bold('\n  Terdapat pengujian yang gagal, silakan periksa rincian di atas.\n')));
  }

  process.exit(failedCount === 0 ? 0 : 1);
}

runTests();
