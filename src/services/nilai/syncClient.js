const config = require('../../config');

/**
 * Client untuk panggilan antar-service dari Service Nilai ke Service Transkrip
 * Sesuai arsitektur: Seluruh akses wajib melalui API Gateway (port 3000), bukan direct call.
 */
class TranskripSyncClient {
  constructor() {
    this.gatewayUrl = `http://localhost:${config.gateway.port}`;
    this.clientId = 'service-nilai';
    this.clientSecret = 'secret-service-nilai-xyz';
    this.cachedToken = null;
    this.tokenExpiry = null;
  }

  /**
   * Memperoleh Service Token dari Gateway (POST /auth/service)
   */
  async getServiceToken() {
    // Gunakan cache jika masih valid
    if (this.cachedToken && this.tokenExpiry && Date.now() < this.tokenExpiry - 30000) {
      return this.cachedToken;
    }

    console.log('[SERVICE NILAI] Meminta token service ke API Gateway (POST /auth/service)...');
    const response = await fetch(`${this.gatewayUrl}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        clientId: this.clientId,
        clientSecret: this.clientSecret
      })
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(`Gagal memperoleh service token: ${err.reason || err.error || response.statusText}`);
    }

    const data = await response.json();
    this.cachedToken = data.token;
    // Set expiry 4.5 menit (karena masa berlaku 5 menit)
    this.tokenExpiry = Date.now() + 4.5 * 60 * 1000;
    return this.cachedToken;
  }

  /**
   * Mengirim request sinkronisasi transkrip ke Gateway (POST /transkrip/sinkron)
   */
  async syncTranskrip(payload) {
    const serviceToken = await this.getServiceToken();

    console.log('[SERVICE NILAI] Mengirim data sinkronisasi transkrip ke API Gateway (POST /transkrip/sinkron)...');
    const response = await fetch(`${this.gatewayUrl}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${serviceToken}`
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(`Gagal sinkronisasi transkrip: ${err.reason || err.error || response.statusText}`);
    }

    return await response.json();
  }
}

module.exports = new TranskripSyncClient();
