import { SecurityHeadersOptions } from '../types.js';

export function getSecurityHeaders(options: boolean | SecurityHeadersOptions = true): Record<string, string> {
  if (!options) return {};

  const opts: SecurityHeadersOptions = typeof options === 'boolean' ? {} : options;

  const headers: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': opts.referrerPolicy || 'strict-origin-when-cross-origin',
    'Permissions-Policy': opts.permissionsPolicy || 'camera=(), microphone=(), geolocation=()',
  };

  if (opts.xFrameOptions !== false) {
    headers['X-Frame-Options'] = opts.xFrameOptions || 'SAMEORIGIN';
  }

  if (opts.hsts !== false) {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
  }

  if (opts.contentSecurityPolicy) {
    if (typeof opts.contentSecurityPolicy === 'string') {
      headers['Content-Security-Policy'] = opts.contentSecurityPolicy;
    }
  }

  return headers;
}
