const express = require('express');
const config = require('../../config');
const { getDatabase } = require('../../database/connection');
const { verifyServiceAccess } = require('../../shared/authMiddleware');

const app = express();
app.use(express.json());

// Terapkan Zero Trust verification pada seluruh route di Service Transkrip
app.use(verifyServiceAccess);

const db = getDatabase();

// Konversi bobot nilai untuk perhitungan IPK
function getBobot(huruf) {
  switch ((huruf || '').toUpperCase()) {
    case 'A': return 4.0;
    case 'B': return 3.0;
    case 'C': return 2.0;
    case 'D': return 1.0;
    default: return 0.0;
  }
}

/**
 * GET /transkrip/:nim
 * Mahasiswa: Hanya NIM miliknya
 * Admin: Semua NIM
 */
app.get('/transkrip/:nim', (req, res) => {
  const targetNim = req.params.nim;
  const user = req.user;

  // Verifikasi ulang prinsip Zero Trust (Defense-in-depth)
  if (user.role === 'mahasiswa' && user.identifier !== targetNim) {
    return res.status(403).json({
      error: 'Forbidden: Mahasiswa hanya boleh melihat transkrip miliknya sendiri',
      code: 'NIM_FORBIDDEN'
    });
  }

  if (user.role !== 'mahasiswa' && user.role !== 'admin') {
    return res.status(403).json({
      error: 'Forbidden: Role ini tidak diizinkan mengakses transkrip',
      code: 'ROLE_FORBIDDEN'
    });
  }

  try {
    const student = db.prepare("SELECT id, identifier AS nim, nama FROM users WHERE identifier = ? AND role = 'mahasiswa'").get(targetNim);
    if (!student) {
      return res.status(404).json({ error: `Mahasiswa dengan NIM ${targetNim} tidak ditemukan` });
    }

    const rows = db.prepare(`
      SELECT 
        id,
        kode_mk,
        nama_mk,
        sks,
        nilai_huruf,
        synced_at
      FROM transkrip
      WHERE nim = ?
      ORDER BY kode_mk
    `).all(targetNim);

    // Hitung total SKS dan IPK
    let totalSks = 0;
    let totalBobotSks = 0;
    rows.forEach(item => {
      totalSks += item.sks;
      totalBobotSks += item.sks * getBobot(item.nilai_huruf);
    });

    const ipk = totalSks > 0 ? (totalBobotSks / totalSks).toFixed(2) : '0.00';

    return res.json({
      status: 'success',
      mahasiswa: {
        nim: student.nim,
        nama: student.nama
      },
      summary: {
        totalMataKuliah: rows.length,
        totalSks,
        ipk: parseFloat(ipk)
      },
      transkrip: rows
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * POST /transkrip/sinkron
 * HANYA Service Nilai (Role 'service'). Token user mana pun ditolak.
 */
app.post('/transkrip/sinkron', (req, res) => {
  const user = req.user;

  // Verifikasi ketat role: Harus 'service'
  if (user.role !== 'service') {
    return res.status(403).json({
      error: 'Forbidden: Hanya token service internal yang diizinkan melakukan sinkronisasi transkrip. Token user ditolak.',
      code: 'SERVICE_ROLE_REQUIRED'
    });
  }

  const { items } = req.body;
  if (!items || !Array.isArray(items)) {
    return res.status(400).json({ error: 'Payload items (array) diperlukan untuk sinkronisasi' });
  }

  try {
    const upsertStmt = db.prepare(`
      INSERT INTO transkrip (mahasiswa_id, nim, kode_mk, nama_mk, sks, nilai_huruf, synced_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(mahasiswa_id, kode_mk) DO UPDATE SET
        nilai_huruf = excluded.nilai_huruf,
        sks = excluded.sks,
        nama_mk = excluded.nama_mk,
        synced_at = CURRENT_TIMESTAMP
    `);

    const syncTransaction = db.transaction((records) => {
      for (const item of records) {
        upsertStmt.run(
          item.mahasiswa_id,
          item.nim,
          item.kode_mk,
          item.nama_mk,
          item.sks || 3,
          item.nilai_huruf
        );
      }
    });

    syncTransaction(items);

    console.log(`[SERVICE TRANSKRIP] Berhasil menyinkronkan ${items.length} data nilai ke transkrip mahasiswa.`);

    return res.json({
      status: 'success',
      message: `Berhasil menyinkronkan ${items.length} rekaman nilai ke database transkrip`,
      syncedCount: items.length,
      syncedAt: new Date().toISOString()
    });
  } catch (err) {
    console.error('[SERVICE TRANSKRIP ERROR]', err.message);
    return res.status(500).json({ error: err.message });
  }
});

function startServer(port = config.services.transkrip.port) {
  return app.listen(port, () => {
    console.log(`[SERVICE TRANSKRIP] Berjalan di port ${port}`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };
