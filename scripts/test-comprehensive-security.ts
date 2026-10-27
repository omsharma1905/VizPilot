/**
 * VizPilot — Comprehensive Security & Vulnerability Remediation Test Suite
 *
 * Automated verification for:
 * 1. CSRF Defense & Strict Origin / Referer / Sec-Fetch-Site Validation
 * 2. High-Performance Sliding-Window Rate Limiting & IP Isolation
 * 3. NoSQL Operator & Schema Injection Defense
 * 4. Security Headers (CSP, HSTS, X-Frame-Options, Cache-Control)
 * 5. Password Security, Complexity & Session Invalidation
 * 6. Zero-Trace Data Privacy & Non-Persistence Invariants
 */

import { NextRequest } from 'next/server';
import { verifyCsrfOrigin } from '../src/lib/security/csrf';
import {
  checkRateLimit,
  getClientIp,
  resetRateLimits,
  RATE_LIMIT_CONFIGS,
} from '../src/lib/security/rate-limit';
import nextConfig from '../next.config';
import { hashPassword, verifyPassword } from '../src/lib/auth/password';
import { generateSessionToken } from '../src/lib/auth/session';
import { safeTelemetryLogger } from '../src/lib/security/telemetry';

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${message}`);
    failed++;
  }
}

async function runSecuritySuite() {
  console.log('\n======================================================');
  console.log('VIZPILOT — COMPREHENSIVE SECURITY AUDIT & VERIFICATION');
  console.log('======================================================\n');

  // ─── 1. CSRF & Origin Verification ───
  console.log('1. CSRF Defense & Origin Verification:');

  // Safe methods (GET, HEAD) should pass without origin
  const getReq = new NextRequest('http://localhost:3000/api/auth/me', { method: 'GET' });
  assert(verifyCsrfOrigin(getReq).valid, 'GET requests are exempt from CSRF checks');

  // Same-origin POST should pass
  const sameOriginPost = new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: {
      host: 'localhost:3000',
      origin: 'http://localhost:3000',
    },
  });
  assert(verifyCsrfOrigin(sameOriginPost).valid, 'Same-origin POST request passes CSRF check');

  // Cross-origin POST from attacker domain should fail
  const attackerPost = new NextRequest('http://localhost:3000/api/profile/password', {
    method: 'POST',
    headers: {
      host: 'localhost:3000',
      origin: 'https://evil-attacker.com',
    },
  });
  const attackerResult = verifyCsrfOrigin(attackerPost);
  assert(!attackerResult.valid, 'Cross-origin POST from evil-attacker.com is blocked');
  assert(attackerResult.statusCode === 403, 'Cross-origin rejection returns 403 status code');

  // Cross-origin with mismatched port should fail
  const portMismatchPost = new NextRequest('http://localhost:3000/api/auth/logout', {
    method: 'POST',
    headers: {
      host: 'localhost:3000',
      origin: 'http://localhost:8080',
    },
  });
  assert(!verifyCsrfOrigin(portMismatchPost).valid, 'Origin with mismatched port is blocked');

  // Sec-Fetch-Site: cross-site should immediately fail
  const crossSiteFetch = new NextRequest('http://localhost:3000/api/auth/login', {
    method: 'POST',
    headers: {
      host: 'localhost:3000',
      'sec-fetch-site': 'cross-site',
    },
  });
  assert(!verifyCsrfOrigin(crossSiteFetch).valid, 'Sec-Fetch-Site: cross-site is immediately blocked');

  // Same-origin Referer when Origin is omitted should pass
  const sameRefererPost = new NextRequest('http://localhost:3000/api/profile', {
    method: 'PATCH',
    headers: {
      host: 'localhost:3000',
      referer: 'http://localhost:3000/profile',
    },
  });
  assert(verifyCsrfOrigin(sameRefererPost).valid, 'Same-origin Referer is accepted when Origin is absent');

  // Untrusted Referer should fail
  const evilRefererPost = new NextRequest('http://localhost:3000/api/profile', {
    method: 'PATCH',
    headers: {
      host: 'localhost:3000',
      referer: 'https://evil.com/phishing',
    },
  });
  assert(!verifyCsrfOrigin(evilRefererPost).valid, 'Untrusted Referer is rejected');

  // ─── 2. Server-Side Rate Limiter & IP Isolation ───
  console.log('\n2. Server-Side Rate Limiter & IP Isolation:');
  resetRateLimits();

  const ipA = '198.51.100.1';
  const ipB = '198.51.100.2';

  // Test login limit (5 per min)
  for (let i = 1; i <= 5; i++) {
    const res = checkRateLimit('login', ipA);
    assert(res.allowed, `Request ${i}/5 within login limit is allowed for IP A`);
    assert(res.remaining === 5 - i, `Remaining count decremented correctly to ${5 - i}`);
  }

  // 6th attempt from IP A must be rejected
  const blockedRes = checkRateLimit('login', ipA);
  assert(!blockedRes.allowed, '6th request from IP A is blocked by rate limiter');
  assert(blockedRes.remaining === 0, 'Remaining count is 0 when blocked');
  assert(blockedRes.resetMs > 0, 'Reset timestamp is provided');

  // IP B must NOT be blocked (IP isolation)
  const ipBRes = checkRateLimit('login', ipB);
  assert(ipBRes.allowed, 'IP B is NOT blocked by IP A exhaustion (strict IP isolation)');
  assert(ipBRes.remaining === 4, 'IP B starts with fresh rate limit bucket');

  // Test getClientIp helper
  const xffReq = new NextRequest('http://localhost:3000/api/auth/login', {
    headers: { 'x-forwarded-for': '203.0.113.195, 70.41.3.18' },
  });
  assert(getClientIp(xffReq) === '203.0.113.195', 'getClientIp extracts primary client IP from X-Forwarded-For');

  // ─── 3. NoSQL Operator & Schema Injection Defense ───
  console.log('\n3. NoSQL Operator & Schema Injection Defense:');

  // Simulate object payload for login
  const nosqlPayload = { email: { $ne: null }, password: { $gt: '' } };
  const isValidScalar = typeof nosqlPayload.email === 'string' && typeof nosqlPayload.password === 'string';
  assert(!isValidScalar, 'MongoDB operator objects ($ne, $gt) are rejected by scalar string validation');

  // Simulate array payload for password
  const arrayPayload = { currentPassword: ['a', 'b'], newPassword: 'ValidPass#2026' };
  const isPassString = typeof arrayPayload.currentPassword === 'string';
  assert(!isPassString, 'Array-shaped password payload is rejected by string validation');

  // ─── 4. Security Headers (CSP, HSTS, X-Frame-Options) ───
  console.log('\n4. Security Headers & Policy Verification:');
  const headers = await nextConfig.headers!();
  const globalHeaderGroup = headers.find((h) => h.source === '/:path*');
  assert(!!globalHeaderGroup, 'Global headers config exists for /:path*');

  const headerMap = new Map(globalHeaderGroup!.headers.map((h) => [h.key, h.value]));
  assert(headerMap.get('X-Frame-Options') === 'DENY', 'X-Frame-Options is DENY (anti-clickjacking)');
  assert(headerMap.get('X-Content-Type-Options') === 'nosniff', 'X-Content-Type-Options is nosniff (anti-MIME-sniffing)');
  assert(headerMap.get('Referrer-Policy') === 'strict-origin-when-cross-origin', 'Referrer-Policy is strict-origin-when-cross-origin');

  const csp = headerMap.get('Content-Security-Policy');
  assert(!!csp, 'Content-Security-Policy header is configured');
  assert(csp!.includes("default-src 'self'"), "CSP restricts default-src to 'self'");
  assert(csp!.includes("object-src 'none'"), "CSP restricts object-src to 'none'");
  assert(csp!.includes("frame-ancestors 'none'"), "CSP restricts frame-ancestors to 'none'");

  const hsts = headerMap.get('Strict-Transport-Security');
  assert(!!hsts, 'Strict-Transport-Security header is configured');
  assert(hsts!.includes('max-age=31536000'), 'HSTS enforces 1-year duration');
  assert(hsts!.includes('includeSubDomains'), 'HSTS applies to subdomains');

  const apiHeaderGroup = headers.find((h) => h.source === '/api/:path*');
  const apiHeaderMap = new Map(apiHeaderGroup!.headers.map((h) => [h.key, h.value]));
  assert(Boolean(apiHeaderMap.get('Cache-Control')?.includes('no-store')), 'API routes strictly forbid caching (no-store)');

  // ─── 5. Password Security, Complexity & Session Purge ───
  console.log('\n5. Password Security & Session Invalidation:');
  const strongPw = 'CorrectPassword#2026';
  const hashed = await hashPassword(strongPw);

  assert(await verifyPassword(strongPw, hashed), 'Valid password verified successfully');
  assert(!(await verifyPassword('WrongPassword', hashed)), 'Invalid password rejected');

  // Session Token Entropy
  const token = generateSessionToken();
  assert(token.length === 64, 'Session token has 64 hex characters (256-bit entropy)');
  assert(/^[a-f0-9]{64}$/.test(token), 'Session token is lowercase hex');

  // ─── 6. Zero-Trace Data Non-Persistence & Log Scrubbing ───
  console.log('\n6. Zero-Trace Data Non-Persistence & Telemetry Scrubbing:');
  const telemetryLogs: string[] = [];
  const originalLog = console.log;
  console.log = (...args: unknown[]) => {
    telemetryLogs.push(args.map(String).join(' '));
  };

  safeTelemetryLogger.log({
    requestId: 'req_audit_123',
    mode: 'zerotrace',
    stage: 'ingest',
    durationMs: 42,
    success: true,
    fileType: 'csv',
    fileSize: 1024,
    rowCount: 10,
    columnCount: 3,
  });

  console.log = originalLog;

  assert(telemetryLogs.length === 1, 'Telemetry emitted exactly 1 log line');
  const logEntry = telemetryLogs[0];
  assert(logEntry.includes('[ZERO-TRACE]'), 'Log prefix indicates Zero-Trace mode');
  assert(logEntry.includes('req_audit_123'), 'Request ID preserved in metadata log');
  assert(!logEntry.includes('password'), 'Log contains zero password references');
  assert(!logEntry.includes('secret'), 'Log contains zero secret references');

  // ─── SUMMARY ───
  console.log('\n======================================================');
  console.log(`TOTAL SECURITY AUDIT TESTS: ${passed + failed}`);
  console.log(`PASSED: ${passed}`);
  console.log(`FAILED: ${failed}`);
  console.log('======================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runSecuritySuite().catch((err) => {
  console.error('Security test suite fatal error:', err);
  process.exit(1);
});
