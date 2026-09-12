export interface WebKernelConfig {
  siteId?: string;
  pairingSecret?: string;
  apiUrl?: string;
  waf?: WafOptions;
  securityHeaders?: boolean | SecurityHeadersOptions;
  rateLimit?: RateLimitOptions;
  debug?: boolean;
}

export interface WafOptions {
  enabled?: boolean;
  mode?: 'block' | 'monitor';
  bannedIps?: string[];
  whitelistPaths?: (string | RegExp)[];
  customRules?: Record<string, RegExp | string>;
}

export interface SecurityHeadersOptions {
  contentSecurityPolicy?: string | boolean;
  hsts?: boolean;
  xFrameOptions?: 'DENY' | 'SAMEORIGIN' | false;
  xContentTypeOptions?: boolean;
  referrerPolicy?: string;
  permissionsPolicy?: string;
}

export interface RateLimitOptions {
  enabled?: boolean;
  requestsPerMinute?: number;
  burstLimit?: number;
}

export interface ThreatInspectionResult {
  blocked: boolean;
  type?: 'sqli' | 'xss' | 'traversal' | 'rce' | 'wp_probe' | 'wrappers' | 'banned_ip' | 'rate_limit' | string;
  source?: 'QUERY' | 'PATH' | 'HEADER' | 'IP';
  key?: string;
  value?: string;
  ruleName?: string;
}

export interface HandshakePayload {
  siteId: string;
  timestamp: string | number;
  nonce: string;
  status: string;
  version: string;
  platform: string;
  health: {
    status: 'healthy' | 'degraded' | 'error';
    uptime: number;
    wafEnabled: boolean;
  };
}
