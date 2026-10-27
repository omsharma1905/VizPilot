import { NextRequest, NextResponse } from 'next/server';

/**
 * VizPilot CSRF Defense & Origin Verification
 *
 * Enforces strict Origin and Referer validation on state-changing HTTP methods
 * (POST, PATCH, PUT, DELETE) to protect authenticated session cookies against
 * Cross-Site Request Forgery (CSRF).
 */

export interface CsrfValidationResult {
  valid: boolean;
  reason?: string;
  statusCode?: number;
}

const STATE_CHANGING_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

/**
 * Validates request Origin and Referer headers against the target Host.
 */
export function verifyCsrfOrigin(request: NextRequest): CsrfValidationResult {
  const method = request.method.toUpperCase();

  // Safe HTTP methods do not mutate state
  if (!STATE_CHANGING_METHODS.has(method)) {
    return { valid: true };
  }

  // 1. Inspect Sec-Fetch-Site metadata if sent by modern browsers
  const secFetchSite = request.headers.get('sec-fetch-site');
  if (secFetchSite === 'cross-site') {
    return {
      valid: false,
      reason: 'Cross-site mutation blocked by Sec-Fetch-Site policy.',
      statusCode: 403,
    };
  }

  // Determine host of current target
  const hostHeader = request.headers.get('x-forwarded-host') || request.headers.get('host');
  const targetHost = hostHeader ? hostHeader.split(':')[0].toLowerCase() : null;
  const targetPort = hostHeader && hostHeader.includes(':') ? hostHeader.split(':')[1] : null;

  // 2. Validate Origin header if present
  const origin = request.headers.get('origin');
  if (origin) {
    try {
      const originUrl = new URL(origin);
      const originHost = originUrl.hostname.toLowerCase();
      const originPort = originUrl.port || (originUrl.protocol === 'https:' ? '443' : '80');

      if (targetHost && originHost !== targetHost) {
        return {
          valid: false,
          reason: `Origin header '${originUrl.host}' does not match host '${hostHeader}'.`,
          statusCode: 403,
        };
      }

      // Check port if specified on both
      if (targetPort && originUrl.port && originUrl.port !== targetPort) {
        return {
          valid: false,
          reason: `Origin port '${originUrl.port}' does not match host port '${targetPort}'.`,
          statusCode: 403,
        };
      }

      return { valid: true };
    } catch {
      return {
        valid: false,
        reason: 'Malformed Origin header.',
        statusCode: 400,
      };
    }
  }

  // 3. Fallback to Referer header if Origin is not supplied
  const referer = request.headers.get('referer');
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const refererHost = refererUrl.hostname.toLowerCase();

      if (targetHost && refererHost !== targetHost) {
        return {
          valid: false,
          reason: `Referer header '${refererUrl.host}' does not match host '${hostHeader}'.`,
          statusCode: 403,
        };
      }

      return { valid: true };
    } catch {
      return {
        valid: false,
        reason: 'Malformed Referer header.',
        statusCode: 400,
      };
    }
  }

  // If neither Origin nor Referer is present, request is either direct, curl/test runner,
  // or a non-browser client. Permitted unless Sec-Fetch-Site blocked it above.
  return { valid: true };
}

/**
 * Returns a JSON 403 response if CSRF verification fails; otherwise null.
 */
export function assertCsrfSafe(request: NextRequest): NextResponse | null {
  const result = verifyCsrfOrigin(request);
  if (!result.valid) {
    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'CSRF_FORBIDDEN',
          message: result.reason || 'Cross-site request prohibited.',
        },
      },
      {
        status: result.statusCode || 403,
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
          'Pragma': 'no-cache',
          'Expires': '0',
        },
      }
    );
  }
  return null;
}
