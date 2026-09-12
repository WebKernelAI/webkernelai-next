import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Signer } from '../src/core/signer.ts';
import { Waf } from '../src/core/waf.ts';

test('Signer: generates and verifies HMAC-SHA256 signature matching protocol', async () => {
  const secret = 'wk_sec_test_secret_key_1234567890';
  const payload = JSON.stringify({ action: 'ping', siteId: 'wk_site_123' });
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = Signer.generateNonce(16);

  const signature = await Signer.generateSignature(payload, timestamp, nonce, secret);
  assert.ok(typeof signature === 'string');
  assert.equal(signature.length, 64); // SHA-256 hex string

  // Valid verification
  const isValid = await Signer.verifySignature(payload, timestamp, nonce, signature, secret, 300);
  assert.equal(isValid, true);

  // Tampered payload
  const isTampered = await Signer.verifySignature(payload + 'tampered', timestamp, nonce, signature, secret, 300);
  assert.equal(isTampered, false);

  // Expired timestamp (>300 seconds ago)
  const expiredTimestamp = timestamp - 400;
  const expiredSignature = await Signer.generateSignature(payload, expiredTimestamp, nonce, secret);
  const isExpired = await Signer.verifySignature(payload, expiredTimestamp, nonce, expiredSignature, secret, 300);
  assert.equal(isExpired, false);
});

test('Waf: intercepts SQL injection and XSS payloads', () => {
  const waf = new Waf();

  // Clean request
  const cleanResult = waf.inspect('/products', new URLSearchParams({ id: '123', category: 'shoes' }));
  assert.equal(cleanResult.blocked, false);

  // SQL Injection in query
  const sqliResult = waf.inspect('/api/search', new URLSearchParams({ q: "1' UNION SELECT null, null--" }));
  assert.equal(sqliResult.blocked, true);
  assert.equal(sqliResult.type, 'sqli');

  // XSS in query
  const xssResult = waf.inspect('/search', new URLSearchParams({ q: '<script>alert(1)</script>' }));
  assert.equal(xssResult.blocked, true);
  assert.equal(xssResult.type, 'xss');

  // Path traversal in path
  const traversalResult = waf.inspect('/static/../../etc/passwd', new URLSearchParams());
  assert.equal(traversalResult.blocked, true);
  assert.equal(traversalResult.type, 'traversal');
});

test('Waf: respects IP blacklist and whitelist paths', () => {
  const waf = new Waf({
    bannedIps: ['192.168.1.100'],
    whitelistPaths: ['/api/webhook/stripe'],
  });

  // Banned IP blocked
  const ipBlocked = waf.inspect('/dashboard', new URLSearchParams(), '192.168.1.100');
  assert.equal(ipBlocked.blocked, true);
  assert.equal(ipBlocked.type, 'banned_ip');

  // Whitelisted path bypassed even with suspicious looking words
  const whitelisted = waf.inspect('/api/webhook/stripe', new URLSearchParams({ event: 'select' }));
  assert.equal(whitelisted.blocked, false);
});
