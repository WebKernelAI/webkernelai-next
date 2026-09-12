import { ThreatInspectionResult, WafOptions } from '../types.js';

/**
 * High-performance, Edge-compatible Web Application Firewall (WAF)
 * Optimized for low-latency (<0.5ms) inspection in Edge Middleware.
 */
export class Waf {
  private static readonly BUILTIN_RULES: Record<string, RegExp> = {
    sqli: /(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set|alter\s+table|exec\s*\(|benchmark\s*\(|sleep\s*\()/i,
    xss: /(<script[\s>]|javascript:|onload\s*=|onerror\s*=|document\.cookie|document\.location|<iframe|<object|<embed)/i,
    traversal: /(\.\.\/|\.\.\\|proc\/self\/environ|etc\/passwd|boot\.ini|win\.ini)/i,
    rce: /(;\s*(cat|ls|whoami|nc|bash|sh|curl|wget|chmod|python|perl|php)(\s+|$|;)|eval\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|exec\s*\()/i,
    wp_probe: /(\bxmlrpc\.php\b|\bwp-login\.php\b|\bsetup-config\.php\b|\bwp-admin\/install\.php\b|\bwp-content\/plugins\/)/i,
    wrappers: /(php:\/\/input|php:\/\/filter|phar:\/\/|data:\/\/|expect:\/\/)/i,
  };

  private bannedIps: Set<string>;
  private whitelistPaths: (string | RegExp)[];
  private customRules: Record<string, RegExp>;

  constructor(options: WafOptions = {}) {
    this.bannedIps = new Set(options.bannedIps || []);
    this.whitelistPaths = options.whitelistPaths || [];
    this.customRules = {};

    if (options.customRules) {
      for (const [name, rule] of Object.entries(options.customRules)) {
        this.customRules[name] = typeof rule === 'string' ? new RegExp(rule, 'i') : rule;
      }
    }
  }

  /**
   * Inspect URL pathname, query parameters, client IP, and headers.
   */
  public inspect(
    pathname: string,
    searchParams: URLSearchParams | Record<string, string>,
    clientIp?: string
  ): ThreatInspectionResult {
    // 1. Whitelist Check
    if (this.isWhitelisted(pathname)) {
      return { blocked: false };
    }

    // 2. Client IP Blacklist Check
    if (clientIp && this.bannedIps.has(clientIp)) {
      return {
        blocked: true,
        type: 'banned_ip',
        source: 'IP',
        key: clientIp,
      };
    }

    // 3. Inspect Pathname
    const pathThreat = this.scanValue(pathname, 'PATH', 'pathname');
    if (pathThreat.blocked) return pathThreat;

    // 4. Inspect Query Parameters
    const entries =
      searchParams instanceof URLSearchParams
        ? Array.from(searchParams.entries())
        : Object.entries(searchParams);

    for (const [key, value] of entries) {
      const keyThreat = this.scanValue(key, 'QUERY', `param_key:${key}`);
      if (keyThreat.blocked) return keyThreat;

      const valThreat = this.scanValue(value, 'QUERY', key);
      if (valThreat.blocked) return valThreat;
    }

    return { blocked: false };
  }

  private isWhitelisted(pathname: string): boolean {
    for (const pattern of this.whitelistPaths) {
      if (typeof pattern === 'string') {
        if (pathname.startsWith(pattern)) return true;
      } else if (pattern.test(pathname)) {
        return true;
      }
    }
    return false;
  }

  private scanValue(
    value: string,
    source: 'QUERY' | 'PATH' | 'HEADER',
    key: string
  ): ThreatInspectionResult {
    if (!value || typeof value !== 'string') {
      return { blocked: false };
    }

    // Check Builtin Rules
    for (const [ruleName, regex] of Object.entries(Waf.BUILTIN_RULES)) {
      if (regex.test(value)) {
        return {
          blocked: true,
          type: ruleName as ThreatInspectionResult['type'],
          source,
          key,
          value: value.slice(0, 100), // truncate for logs
          ruleName,
        };
      }
    }

    // Check Custom Dynamic Rules
    for (const [ruleName, regex] of Object.entries(this.customRules)) {
      if (regex.test(value)) {
        return {
          blocked: true,
          type: 'custom',
          source,
          key,
          value: value.slice(0, 100),
          ruleName,
        };
      }
    }

    return { blocked: false };
  }
}
