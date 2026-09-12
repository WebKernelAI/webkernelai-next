# WebKernelAI Next.js SDK (`webkernelai-next`)

Official Next.js SDK for **[WebKernelAI](https://webkernelai.com)** — The next-generation infrastructure for **Technical SEO Intelligence**, **Zero-Trust Application Security**, and **Answer Engine Optimization (AEO / GEO)**.

This SDK provides Edge-compatible Web Application Firewall (WAF) filtering, cryptographic HMAC-SHA256 request verification, automated security headers injection, sliding-window rate limiting, and Schema.org JSON-LD generation for **Next.js 13, 14, and 15+ (App Router & Pages Router)**.

---

## 🚀 Key Features

- 🛡️ **Edge-Compatible WAF (Web Application Firewall)**: High-speed (<0.5ms) inspection of URL pathnames and query strings to block SQL Injection (UNION / Blind SQLi), Cross-Site Scripting (XSS), Path Traversal (`../../etc/passwd`), Command Injection (RCE), and PHP/WordPress bot scanners.
- ⚡ **Zero Cold-Start Edge Middleware**: Designed to run directly in Vercel Edge Middleware or Cloudflare Workers without native C++ or heavyweight dependencies.
- 🔐 **Cryptographic HMAC-SHA256 Handshake**: Validates requests from the WebKernelAI Cloud dashboard with standard Web Crypto APIs, nonces, and 300-second replay attack protection.
- ⏱️ **Sliding-Window Rate Limiter**: Built-in memory rate limiter to protect against bot scrapers and automated attacks.
- 🌐 **Automated Security Headers**: Injects enterprise-grade HTTP headers (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Strict-Transport-Security`, `Permissions-Policy`).
- 🤖 **Dynamic JSON-LD Schema (AEO / GEO)**: React Server Component `<WebKernelJsonLd />` to inject structured schema markup for Google, Perplexity, and AI search crawlers.

---

## 📦 Installation

```bash
npm install @webkernelai/next
# or
pnpm add @webkernelai/next
# or
yarn add @webkernelai/next
```

---

## ⚡ Quick Start

### 1. Configure Environment Variables (`.env.local`)

Generate your pairing credentials from your WebKernelAI dashboard:

```env
WEBKERNELAI_SITE_ID=wk_site_xxxxxxxx
WEBKERNELAI_PAIRING_SECRET=wk_sec_xxxxxxxxxxxxxxxx
WEBKERNELAI_API_URL=https://api.webkernelai.com
```

---

### 2. Edge Middleware Protection (`middleware.ts`)

Create or update `middleware.ts` in your Next.js project root:

```typescript
import { createWebKernelMiddleware } from '@webkernelai/next/middleware';

export const middleware = createWebKernelMiddleware({
  siteId: process.env.WEBKERNELAI_SITE_ID,
  pairingSecret: process.env.WEBKERNELAI_PAIRING_SECRET,
  waf: {
    enabled: true,
    mode: 'block', // 'block' returns 403; 'monitor' attaches threat headers downstream
  },
  rateLimit: {
    enabled: true,
    requestsPerMinute: 120,
  },
  securityHeaders: true,
});

export const config = {
  matcher: [
    /*
     * Match all request paths except static files, _next, favicon.ico
     */
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
```

---

### 3. Cloud Handshake & Health Probe (`app/api/webkernelai/route.ts`)

Connect your Next.js application to the WebKernelAI Cloud dashboard for threat telemetry and health monitoring:

```typescript
import { createWebKernelApiHandler } from '@webkernelai/next/api';

const handler = createWebKernelApiHandler();

export { handler as GET, handler as POST };
```

---

### 4. Dynamic Schema & AEO Optimization (`app/layout.tsx`)

Render structured data directly in React Server Components:

```tsx
import { WebKernelJsonLd } from '@webkernelai/next/seo';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: 'Your Next.js App',
    url: 'https://example.com',
  };

  return (
    <html lang="en">
      <head>
        <WebKernelJsonLd schema={schema} />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

---

## 🛠️ Configuration Options

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `siteId` | `string` | `process.env.WEBKERNELAI_SITE_ID` | Your WebKernelAI unique site identifier |
| `pairingSecret` | `string` | `process.env.WEBKERNELAI_PAIRING_SECRET` | 256-bit cryptographic HMAC secret |
| `waf.enabled` | `boolean` | `true` | Enable/disable embedded WAF threat scanning |
| `waf.mode` | `'block' \| 'monitor'` | `'block'` | `'block'` rejects with 403; `'monitor'` forwards flags |
| `waf.bannedIps` | `string[]` | `[]` | Array of IP addresses to automatically deny |
| `waf.whitelistPaths` | `(string \| RegExp)[]` | `[]` | Paths excluded from threat inspection (e.g. webhooks) |
| `rateLimit.enabled` | `boolean` | `true` | Enable sliding window rate limiting |
| `rateLimit.requestsPerMinute` | `number` | `120` | Max requests per IP per minute |
| `securityHeaders` | `boolean \| SecurityHeadersOptions` | `true` | Injects production HTTP security headers |

---

## 🔒 Security & Replay Attack Guarantee

WebKernelAI Next.js signatures use standard **HMAC-SHA256** message authentication with timestamp freshness validation (`maxAge = 300s`) and constant-time string comparisons to prevent timing attacks, spoofing, and replay exploits.

---

## 📄 License

MIT © [WebKernelAI](https://webkernelai.com)
