const jwt = require('jsonwebtoken');
const config = require('../config');
const { getDatabase } = require('../database/connection');

/**
 * Policy Engine / Policy Administrator (NIST SP 800-207 PE/PA)
 * Bertugas mengevaluasi allow / deny berdasarkan:
 * - Kredensial dan Token JWT
 * - Konteks Device (X-Device-ID terdaftar di database)
 * - Konteks Jam Akses (07.00 - 21.00)
 * - Atribut Database (Kepemilikan data dosen/mahasiswa, status finalisasi)
 */
class PolicyEngine {
  constructor() {
    this.db = getDatabase();
  }

  /**
   * Mengecek apakah jam saat ini berada di dalam rentang jam akses yang diizinkan (07.00 - 21.00)
   * Mendukung header simulasi 'X-Simulate-Hour' untuk kemudahan demo.
   */
  isWithinAccessHours(req) {
    let currentHour;
    if (req.headers['x-simulate-hour'] !== undefined) {
      currentHour = parseInt(req.headers['x-simulate-hour'], 10);
    } else {
      currentHour = new Date().getHours();
    }
    const isAllowed = currentHour >= config.accessHours.start && currentHour < config.accessHours.end;
    return {
      isAllowed,
      currentHour,
      allowedRange: `${config.accessHours.start}:00 - ${config.accessHours.end}:00`
    };
  }

  /**
   * Memeriksa apakah device terdaftar untuk user yang bersangkutan
   */
  isDeviceRegistered(userId, deviceId) {
    if (!deviceId) return false;
    const stmt = this.db.prepare('SELECT id FROM devices WHERE user_id = ? AND device_id = ?');
    const device = stmt.get(userId, deviceId);
    return !!device;
  }

  /**
   * Evaluasi Utama Kebijakan Akses (PEP calling PE)
   */
  evaluate(req) {
    const path = (req.originalUrl || req.path || '').split('?')[0];
    const method = req.method.toUpperCase();
    const deviceId = req.headers['x-device-id'] || null;

    // 1. Endpoint /auth/* ditangani langsung oleh Gateway
    if (path.startsWith('/auth/')) {
      return { allowed: true, reason: 'Gateway authentication endpoint handled separately', bypassProxy: true };
    }

    // 2. Token JWT wajib ada untuk semua request selain /auth/*
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        allowed: false,
        reason: 'Token Authorization Bearer tidak ditemukan pada request',
        code: 'TOKEN_MISSING'
      };
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, config.jwt.secret);
    } catch (err) {
      return {
        allowed: false,
        reason: `Verifikasi token JWT gagal: ${err.message}`,
        code: 'TOKEN_INVALID'
      };
    }

    const userRole = decoded.role;
    const userId = decoded.sub; // user ID atau service client ID

    // 3. Panggilan Antar-Service menggunakan Token Service (role: 'service')
    if (userRole === 'service') {
      // Sesuai Tabel 3: Hanya boleh mengakses POST /transkrip/sinkron
      if (path === '/transkrip/sinkron' && method === 'POST') {
        return {
          allowed: true,
          subject: userId,
          role: userRole,
          reason: 'Token service valid untuk sinkronisasi transkrip'
        };
      }
      return {
        allowed: false,
        subject: userId,
        role: userRole,
        reason: `Token service dilarang mengakses endpoint ${method} ${path}`,
        code: 'SERVICE_ENDPOINT_FORBIDDEN'
      };
    }

    // 4. Request dari User (Admin, Dosen, Mahasiswa)
    // Sesuai Bagian 4.3: Wajib membawa header X-Device-ID dan device harus terdaftar
    if (!deviceId) {
      return {
        allowed: false,
        subject: decoded.username || userId,
        role: userRole,
        reason: 'Header X-Device-ID wajib disertakan untuk request user',
        code: 'DEVICE_HEADER_MISSING'
      };
    }

    const deviceValid = this.isDeviceRegistered(decoded.userId, deviceId);
    if (!deviceValid) {
      return {
        allowed: false,
        subject: decoded.username || userId,
        role: userRole,
        reason: `Device '${deviceId}' tidak terdaftar untuk user '${decoded.username}'`,
        code: 'DEVICE_UNREGISTERED'
      };
    }

    // 5. Evaluasi Kebijakan Berdasarkan Tabel 3 (Kepemilikan data & aturan hak akses)

    // A. GET /nilai -> Mahasiswa & Dosen
    if (path === '/nilai' && method === 'GET') {
      if (userRole === 'mahasiswa') {
        return {
          allowed: true,
          subject: decoded.username,
          role: userRole,
          user: decoded,
          reason: 'Mahasiswa diizinkan melihat nilai (dibatasi hanya nilai miliknya)'
        };
      } else if (userRole === 'dosen') {
        return {
          allowed: true,
          subject: decoded.username,
          role: userRole,
          user: decoded,
          reason: 'Dosen diizinkan melihat nilai (dibatasi hanya kelas yang diampu)'
        };
      } else {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Role '${userRole}' tidak diizinkan mengakses data nilai`,
          code: 'ROLE_FORBIDDEN'
        };
      }
    }

    // B. PUT /nilai/:id -> Dosen
    const nilaiMatch = path.match(/^\/nilai\/(\d+)$/);
    if (nilaiMatch && method === 'PUT') {
      const nilaiId = parseInt(nilaiMatch[1], 10);

      if (userRole !== 'dosen') {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: 'Hanya dosen yang berhak mengubah nilai',
          code: 'ROLE_FORBIDDEN'
        };
      }

      // Verifikasi Jam Akses (07.00 - 21.00)
      const hoursCheck = this.isWithinAccessHours(req);
      if (!hoursCheck.isAllowed) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Di luar jam akses perubahan nilai. Jam saat ini: ${hoursCheck.currentHour}:00 (Diizinkan: ${hoursCheck.allowedRange})`,
          code: 'OUTSIDE_ACCESS_HOURS'
        };
      }

      // Verifikasi Kepemilikan Data & Status Finalisasi dari Database
      const nilaiRecord = this.db.prepare(`
        SELECT n.id, n.kelas_id, k.dosen_id, k.is_final, k.nama_mk
        FROM nilai n
        JOIN kelas k ON n.kelas_id = k.id
        WHERE n.id = ?
      `).get(nilaiId);

      if (!nilaiRecord) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Data nilai dengan ID ${nilaiId} tidak ditemukan`,
          code: 'NOT_FOUND'
        };
      }

      if (nilaiRecord.dosen_id !== decoded.userId) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Dosen '${decoded.username}' bukan pengampu kelas mata kuliah ini`,
          code: 'NOT_CLASS_OWNER'
        };
      }

      if (nilaiRecord.is_final === 1) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Nilai tidak dapat diubah karena kelas '${nilaiRecord.nama_mk}' telah difinalisasi`,
          code: 'CLASS_ALREADY_FINALIZED'
        };
      }

      return {
        allowed: true,
        subject: decoded.username,
        role: userRole,
        user: decoded,
        reason: 'Dosen terverifikasi sebagai pengampu kelas, nilai belum final, dan dalam jam akses'
      };
    }

    // C. POST /kelas/:id/finalisasi -> Dosen
    const finalisasiMatch = path.match(/^\/kelas\/(\d+)\/finalisasi$/);
    if (finalisasiMatch && method === 'POST') {
      const kelasId = parseInt(finalisasiMatch[1], 10);

      if (userRole !== 'dosen') {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: 'Hanya dosen yang berhak memfinalisasi nilai kelas',
          code: 'ROLE_FORBIDDEN'
        };
      }

      // Verifikasi Jam Akses (07.00 - 21.00)
      const hoursCheck = this.isWithinAccessHours(req);
      if (!hoursCheck.isAllowed) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Di luar jam akses finalisasi kelas. Jam saat ini: ${hoursCheck.currentHour}:00 (Diizinkan: ${hoursCheck.allowedRange})`,
          code: 'OUTSIDE_ACCESS_HOURS'
        };
      }

      // Verifikasi Kepemilikan Kelas & Status Finalisasi
      const kelasRecord = this.db.prepare('SELECT id, dosen_id, is_final, nama_mk FROM kelas WHERE id = ?').get(kelasId);
      if (!kelasRecord) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Kelas dengan ID ${kelasId} tidak ditemukan`,
          code: 'NOT_FOUND'
        };
      }

      if (kelasRecord.dosen_id !== decoded.userId) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Dosen '${decoded.username}' bukan pengampu kelas '${kelasRecord.nama_mk}'`,
          code: 'NOT_CLASS_OWNER'
        };
      }

      if (kelasRecord.is_final === 1) {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Kelas '${kelasRecord.nama_mk}' sudah pernah difinalisasi sebelumnya`,
          code: 'CLASS_ALREADY_FINALIZED'
        };
      }

      return {
        allowed: true,
        subject: decoded.username,
        role: userRole,
        user: decoded,
        reason: 'Dosen pengampu terverifikasi, kelas belum final, dan dalam jam akses'
      };
    }

    // D. GET /transkrip/:nim -> Mahasiswa (hanya NIM sendiri), Admin (semua NIM)
    const transkripMatch = path.match(/^\/transkrip\/([a-zA-Z0-9]+)$/);
    if (transkripMatch && method === 'GET') {
      const targetNim = transkripMatch[1];

      if (userRole === 'mahasiswa') {
        if (decoded.identifier !== targetNim) {
          return {
            allowed: false,
            subject: decoded.username,
            role: userRole,
            reason: `Mahasiswa '${decoded.username}' (NIM: ${decoded.identifier}) hanya boleh melihat transkrip miliknya sendiri, bukan NIM: ${targetNim}`,
            code: 'NIM_MISMATCH'
          };
        }
        return {
          allowed: true,
          subject: decoded.username,
          role: userRole,
          user: decoded,
          reason: 'Mahasiswa melihat transkrip miliknya sendiri'
        };
      } else if (userRole === 'admin') {
        return {
          allowed: true,
          subject: decoded.username,
          role: userRole,
          user: decoded,
          reason: 'Admin diizinkan melihat transkrip mahasiswa mana pun'
        };
      } else {
        return {
          allowed: false,
          subject: decoded.username,
          role: userRole,
          reason: `Role '${userRole}' tidak diizinkan mengakses data transkrip`,
          code: 'ROLE_FORBIDDEN'
        };
      }
    }

    // E. POST /transkrip/sinkron -> Hanya Token Service!
    if (path === '/transkrip/sinkron' && method === 'POST') {
      // Request yang sampai di sini adalah token user (karena token service ditangani di langkah 3)
      return {
        allowed: false,
        subject: decoded.username,
        role: userRole,
        reason: 'Endpoint /transkrip/sinkron hanya dapat diakses oleh Token Service. Token user ditolak.',
        code: 'USER_TOKEN_REJECTED'
      };
    }

    // Fallback: Endpoint tidak dikenal
    return {
      allowed: false,
      subject: decoded.username || userId,
      role: userRole,
      reason: `Endpoint ${method} ${path} tidak didefinisikan dalam kebijakan akses`,
      code: 'ROUTE_NOT_FOUND'
    };
  }
}

module.exports = new PolicyEngine();
