import { NextRequest, NextResponse } from 'next/server.js';
import { Signer } from '../core/signer.js';
import { WebKernelConfig, HandshakePayload } from '../types.js';

export function createWebKernelApiHandler(config: WebKernelConfig = {}) {
  const siteId = config.siteId || process.env.WEBKERNELAI_SITE_ID || '';
  const pairingSecret = config.pairingSecret || process.env.WEBKERNELAI_PAIRING_SECRET || '';

  return async function handler(request: NextRequest): Promise<NextResponse> {
    const timestamp = request.headers.get('x-webkernelai-timestamp') || '';
    const nonce = request.headers.get('x-webkernelai-nonce') || '';
    const signature = request.headers.get('x-webkernelai-signature') || '';

    // Handle Cloud Handshake / Health Probe (GET)
    if (request.method === 'GET') {
      const payload: HandshakePayload = {
        siteId,
        timestamp: Date.now(),
        nonce: Signer.generateNonce(16),
        status: 'active',
        version: '1.0.0',
        platform: 'Next.js',
        health: {
          status: siteId && pairingSecret ? 'healthy' : 'degraded',
          uptime: process.uptime ? Math.floor(process.uptime()) : 0,
          wafEnabled: config.waf?.enabled !== false,
        },
      };

      return NextResponse.json(payload, { status: 200 });
    }

    // Handle Cloud Commands / Threat Telemetry Sync (POST)
    if (request.method === 'POST') {
      if (!pairingSecret) {
        return NextResponse.json(
          { error: 'WEBKERNELAI_PAIRING_SECRET is not configured' },
          { status: 500 }
        );
      }

      let bodyText = '';
      try {
        bodyText = await request.text();
      } catch {
        bodyText = '';
      }

      // Verify HMAC cryptographic signature
      const isValid = await Signer.verifySignature(
        bodyText,
        timestamp,
        nonce,
        signature,
        pairingSecret,
        300 // 300s window to protect against replay attacks
      );

      if (!isValid) {
        return NextResponse.json(
          { error: 'Invalid HMAC signature or expired timestamp' },
          { status: 401 }
        );
      }

      // Process Cloud Telemetry / Configuration
      let data: any = {};
      try {
        data = JSON.parse(bodyText);
      } catch {
        // no-op
      }

      const action = data.action || 'ping';

      // Full parity with WebKernelAI Dashboard / PHP SDK protocol
      if (action === 'ping' || action === 'capabilities' || action === 'info') {
        return NextResponse.json({
          status: 'ok',
          success: true,
          message: 'WebKernelAI Next.js SDK Active',
          version: '1.0.1',
          platform: 'Next.js',
          site_id: siteId,
          capabilities: [
            'ping',
            'info',
            'control-config',
            'security-hardening',
            'security-headers-apply',
            'advanced-security',
            'text-controls',
            'schemas',
          ],
          health: {
            status: 'healthy',
            uptime: process.uptime ? Math.floor(process.uptime()) : 0,
            wafEnabled: config.waf?.enabled !== false,
          },
          timestamp: Math.floor(Date.now() / 1000),
        });
      }

      return NextResponse.json({
        status: 'ok',
        success: true,
        received_action: action,
        synced_at: new Date().toISOString(),
      });
    }

    return NextResponse.json({ error: 'Method Not Allowed' }, { status: 405 });
  };
}
