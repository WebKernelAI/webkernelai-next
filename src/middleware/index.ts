import { NextRequest, NextResponse } from 'next/server.js';
import { WebKernelConfig } from '../types.js';
import { Waf } from '../core/waf.js';
import { getSecurityHeaders } from '../core/headers.js';
import { RateLimiter } from '../core/rate-limiter.js';

export function createWebKernelMiddleware(config: WebKernelConfig = {}) {
  const waf = new Waf(config.waf);
  const rateLimiter = config.rateLimit?.enabled !== false ? new RateLimiter(config.rateLimit) : null;
  const securityHeaders = getSecurityHeaders(config.securityHeaders ?? true);

  return async function webKernelMiddleware(request: NextRequest) {
    const { pathname, searchParams } = request.nextUrl;

    // Skip Next.js internal static assets & telemetry
    if (
      pathname.startsWith('/_next') ||
      pathname.startsWith('/favicon.ico') ||
      pathname.includes('.')
    ) {
      return NextResponse.next();
    }

    // Resolve client IP (supporting Vercel / Cloudflare headers)
    const clientIp =
      request.headers.get('x-real-ip') ||
      request.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
      '';

    // 1. Rate Limiting Check
    if (rateLimiter) {
      const { allowed } = rateLimiter.check(clientIp);
      if (!allowed) {
        return new NextResponse(
          JSON.stringify({
            error: 'Too Many Requests',
            message: 'Rate limit exceeded. Protected by WebKernelAI.',
          }),
          {
            status: 429,
            headers: {
              'Content-Type': 'application/json',
              'X-RateLimit-Remaining': '0',
              'Retry-After': '60',
              ...securityHeaders,
            },
          }
        );
      }
    }

    // 2. Embedded WAF Threat Inspection
    if (config.waf?.enabled !== false) {
      const threat = waf.inspect(pathname, searchParams, clientIp);

      if (threat.blocked) {
        if (config.waf?.mode === 'monitor') {
          // In monitor mode, pass threat tags downstream
          const requestHeaders = new Headers(request.headers);
          requestHeaders.set('x-webkernelai-threat-detected', '1');
          requestHeaders.set('x-webkernelai-threat-type', threat.type || 'unknown');

          const response = NextResponse.next({
            request: { headers: requestHeaders },
          });
          applyHeaders(response, securityHeaders);
          return response;
        }

        // In block mode, deny request immediately with 403 Forbidden
        return new NextResponse(
          JSON.stringify({
            error: 'Forbidden',
            message: 'Suspicious payload detected by WebKernelAI WAF.',
            threat_type: threat.type,
            reference_id: Math.random().toString(36).substring(2, 10).toUpperCase(),
          }),
          {
            status: 403,
            headers: {
              'Content-Type': 'application/json',
              'X-WebKernelAI-Blocked': 'true',
              ...securityHeaders,
            },
          }
        );
      }
    }

    // 3. Continue Request and Apply Production Security Headers
    const response = NextResponse.next();
    applyHeaders(response, securityHeaders);
    return response;
  };
}

function applyHeaders(response: NextResponse, headers: Record<string, string>): void {
  for (const [key, value] of Object.entries(headers)) {
    if (!response.headers.has(key)) {
      response.headers.set(key, value);
    }
  }
}
