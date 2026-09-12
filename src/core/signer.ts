/**
 * Edge-compatible HMAC-SHA256 Signer matching WebKernelAI PHP SDK Signer specification:
 *   dataToSign = timestamp . '.' . nonce . '.' . sha256(payload)
 *   signature = hmac_sha256(dataToSign, secret)
 */
export class Signer {
  /**
   * Helper to get global Web Crypto or Node.js crypto
   */
  private static getCrypto(): Crypto {
    if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
      return globalThis.crypto;
    }
    // Fallback if imported in pure Node environments without globalThis.crypto
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require('node:crypto');
      return nodeCrypto.webcrypto;
    } catch {
      throw new Error('WebCrypto API is not supported in this runtime environment.');
    }
  }

  /**
   * Compute SHA-256 hash of a string in lowercase hex.
   */
  public static async sha256(message: string): Promise<string> {
    const crypto = this.getCrypto();
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Generate HMAC-SHA256 request signature.
   */
  public static async generateSignature(
    payload: string,
    timestamp: string | number,
    nonce: string,
    secret: string
  ): Promise<string> {
    const crypto = this.getCrypto();
    const payloadHash = await this.sha256(payload);
    const dataToSign = `${timestamp}.${nonce}.${payloadHash}`;

    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const messageData = encoder.encode(dataToSign);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    return Array.from(new Uint8Array(signatureBuffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Verify HMAC-SHA256 request signature with timestamp freshness (replay attack prevention).
   */
  public static async verifySignature(
    payload: string,
    timestamp: string | number,
    nonce: string,
    signature: string,
    secret: string,
    maxAgeSeconds: number = 300
  ): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    const ts = typeof timestamp === 'string' ? parseInt(timestamp, 10) : timestamp;

    if (maxAgeSeconds > 0 && Math.abs(now - ts) > maxAgeSeconds) {
      return false; // Expired or future timestamp (replay attack prevention)
    }

    const expectedSignature = await this.generateSignature(payload, timestamp, nonce, secret);
    return this.timingSafeEqual(expectedSignature, signature);
  }

  /**
   * Generate a cryptographically secure random hex nonce.
   */
  public static generateNonce(length: number = 32): string {
    const crypto = this.getCrypto();
    const byteLength = Math.ceil(length / 2);
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, length);
  }

  /**
   * Constant-time string comparison to mitigate timing attacks.
   */
  private static timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }
}
