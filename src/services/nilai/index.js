const express = require('express');
const config = require('../../config');
const { getDatabase } = require('../../database/connection');
const { verifyServiceAccess } = require('../../shared/authMiddleware');
const syncClient = require('./syncClient');

const app = express();
app.use(express.json());

// Terapkan Zero Trust verification pada seluruh route di Service Nilai
app.use(verifyServiceAccess);

const db = getDatabase();

/**
 * GET /nilai
 * Mahasiswa: Hanya nilai miliknya
 * Dosen: Hanya kelas yang diampu
 */
app.get('/nilai', (req, res) => {
  const user = req.user;

  try {
    if (user.role === 'mahasiswa') {
      const stmt = db.prepare(`
        SELECT 
          n.id AS nilai_id,
          k.kode_mk,
          k.nama_mk,
          k.sks,
          u_dosen.nama AS nama_dosen,
          n.nilai_angka,
          n.nilai_huruf,
          k.is_final
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        JOIN users u_dosen ON k.dosen_id = u_dosen.id
        WHERE n.mahasiswa_id = ?
      `);
      const rows = stmt.all(user.userId);
      return res.json({
        status: 'success',
        role: user.role,
        count: rows.length,
        data: rows
      });
    }

    if (user.role === 'dosen') {
      const stmt = db.prepare(`
        SELECT 
          n.id AS nilai_id,
          k.id AS kelas_id,
          k.kode_mk,
          k.nama_mk,
          u_mhs.identifier AS nim,
          u_mhs.nama AS nama_mahasiswa,
          n.nilai_angka,
          n.nilai_huruf,
          k.is_final
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        JOIN users u_mhs ON n.mahasiswa_id = u_mhs.id
        WHERE k.dosen_id = ?
        ORDER BY k.id, u_mhs.identifier
      `);
      const rows = stmt.all(user.userId);
      return res.json({
        status: 'success',
        role: user.role,
        count: rows.length,
        data: rows
      });
    }

    return res.status(403).json({ error: 'Role tidak diizinkan mengakses data nilai' });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /nilai/:id
 * Dosen: Mengubah nilai pada kelas yang diampu
 */
app.put('/nilai/:id', (req, res) => {
  const nilaiId = parseInt(req.params.id, 10);
  const { nilai_angka, nilai_huruf } = req.body;

  if (nilai_angka === undefined && !nilai_huruf) {
    return res.status(400).json({ error: 'Nilai angka atau nilai huruf wajib diisi' });
  }

  let finalHuruf = nilai_huruf;
  if (!finalHuruf && nilai_angka !== undefined) {
    if (nilai_angka >= 80) finalHuruf = 'A';
    else if (nilai_angka >= 70) finalHuruf = 'B';
    else if (nilai_angka >= 60) finalHuruf = 'C';
    else if (nilai_angka >= 50) finalHuruf = 'D';
    else finalHuruf = 'E';
  }

  try {
    const updateStmt = db.prepare(`
      UPDATE nilai 
      SET nilai_angka = COALESCE(?, nilai_angka),
          nilai_huruf = COALESCE(?, nilai_huruf),
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);
    updateStmt.run(nilai_angka, finalHuruf, nilaiId);

    const updated = db.prepare(`
      SELECT n.id, k.kode_mk, k.nama_mk, u.identifier AS nim, u.nama, n.nilai_angka, n.nilai_huruf
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      JOIN users u ON n.mahasiswa_id = u.id
      WHERE n.id = ?
    `).get(nilaiId);

    return res.json({
      status: 'success',
      message: `Nilai ID ${nilaiId} berhasil diperbarui`,
      data: updated
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * POST /kelas/:id/finalisasi
 * Dosen: Memfinalisasi kelas dan menyinkronkan data ke Service Transkrip melalui Gateway
 */
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const kelasId = parseInt(req.params.id, 10);

  try {
    const kelas = db.prepare('SELECT id, kode_mk, nama_mk, sks FROM kelas WHERE id = ?').get(kelasId);
    if (!kelas) {
      return res.status(404).json({ error: 'Kelas tidak ditemukan' });
    }

    // 1. Ubah status kelas menjadi final
    db.prepare('UPDATE kelas SET is_final = 1, finalized_at = CURRENT_TIMESTAMP WHERE id = ?').run(kelasId);

    // 2. Ambil seluruh data nilai mahasiswa di kelas ini
    const items = db.prepare(`
      SELECT 
        n.mahasiswa_id,
        u.identifier AS nim,
        k.kode_mk,
        k.nama_mk,
        k.sks,
        n.nilai_huruf
      FROM nilai n
      JOIN kelas k ON n.kelas_id = k.id
      JOIN users u ON n.mahasiswa_id = u.id
      WHERE n.kelas_id = ?
    `).all(kelasId);

    // 3. Panggilan Antar-Service ke Service Transkrip melalui Gateway (Port 3000)
    console.log(`[SERVICE NILAI] Kelas ${kelas.kode_mk} (${kelas.nama_mk}) difinalisasi. Menyinkronkan ${items.length} nilai mahasiswa...`);
    const syncResult = await syncClient.syncTranskrip({
      kelasId,
      kodeMk: kelas.kode_mk,
      namaMk: kelas.nama_mk,
      items
    });

    return res.json({
      status: 'success',
      message: `Kelas ${kelas.kode_mk} - ${kelas.nama_mk} berhasil difinalisasi dan disinkronkan ke Service Transkrip`,
      finalizedAt: new Date().toISOString(),
      syncResult
    });
  } catch (err) {
    console.error('[SERVICE NILAI ERROR]', err.message);
    return res.status(500).json({
      error: 'Finalisasi nilai gagal',
      details: err.message
    });
  }
});

function startServer(port = config.services.nilai.port) {
  return app.listen(port, () => {
    console.log(`[SERVICE NILAI] Berjalan di port ${port}`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };
