import { NextRequest, NextResponse } from 'next/server';

/**
 * VizPilot In-Memory Sliding-Window Rate Limiter
 *
 * Protects authentication endpoints, AI recommendation, ingestion, and account
 * mutations from brute-force attacks, credential stuffing, and DoS resource exhaustion.
 */

interface RateLimitRecord {
  timestamps: number[];
}

interface BucketConfig {
  windowMs: number;
  maxRequests: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetMs: number;
}

// In-memory store: Map<"bucket:key", RateLimitRecord>
const rateLimitStore = new Map<string, RateLimitRecord>();

// Default rate-limit configurations by bucket type
export const RATE_LIMIT_CONFIGS: Record<string, BucketConfig> = {
  login: { windowMs: 60 * 1000, maxRequests: 5 },          // 5 attempts / min
  signup: { windowMs: 60 * 1000, maxRequests: 5 },         // 5 attempts / min
  password: { windowMs: 300 * 1000, maxRequests: 5 },      // 5 attempts / 5 mins
  email_verification: { windowMs: 60 * 1000, maxRequests: 5 }, // 5 attempts / min
  recommend: { windowMs: 60 * 1000, maxRequests: 20 },     // 20 requests / min
  ingest: { windowMs: 60 * 1000, maxRequests: 30 },        // 30 uploads / min
  general: { windowMs: 60 * 1000, maxRequests: 60 },       // 60 requests / min
};

/**
 * Extracts the real client IP address from request headers.
 */
export function getClientIp(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded.split(',')[0].trim();
    if (first) return first;
  }
  const realIp = request.headers.get('x-real-ip');
  if (realIp) return realIp.trim();

  return '127.0.0.1';
}

/**
 * Checks and increments rate limit for a given bucket and key.
 */
export function checkRateLimit(
  bucketName: keyof typeof RATE_LIMIT_CONFIGS | string,
  key: string,
  customConfig?: BucketConfig
): RateLimitResult {
  const config = customConfig || RATE_LIMIT_CONFIGS[bucketName] || RATE_LIMIT_CONFIGS.general;
  const now = Date.now();
  const cutoff = now - config.windowMs;
  const storeKey = `${bucketName}:${key}`;

  let record = rateLimitStore.get(storeKey);
  if (!record) {
    record = { timestamps: [] };
    rateLimitStore.set(storeKey, record);
  }

  // Filter out timestamps outside the sliding window
  record.timestamps = record.timestamps.filter((t) => t > cutoff);

  if (record.timestamps.length >= config.maxRequests) {
    const oldestTimestamp = record.timestamps[0];
    const resetMs = Math.max(0, oldestTimestamp + config.windowMs - now);

    return {
      allowed: false,
      limit: config.maxRequests,
      remaining: 0,
      resetMs,
    };
  }

  // Record this request
  record.timestamps.push(now);

  const resetMs = config.windowMs;
  const remaining = Math.max(0, config.maxRequests - record.timestamps.length);

  return {
    allowed: true,
    limit: config.maxRequests,
    remaining,
    resetMs,
  };
}

/**
 * Creates a standardized 429 Too Many Requests response with RateLimit headers.
 */
export function rateLimitResponse(result: RateLimitResult): NextResponse {
  const retryAfterSec = Math.ceil(result.resetMs / 1000);

  return NextResponse.json(
    {
      success: false,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Too many requests. Please try again in ${retryAfterSec} second${retryAfterSec === 1 ? '' : 's'}.`,
        retryAfter: retryAfterSec,
      },
    },
    {
      status: 429,
      headers: {
        'Retry-After': retryAfterSec.toString(),
        'X-RateLimit-Limit': result.limit.toString(),
        'X-RateLimit-Remaining': result.remaining.toString(),
        'X-RateLimit-Reset': Math.ceil((Date.now() + result.resetMs) / 1000).toString(),
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'Expires': '0',
      },
    }
  );
}

/**
 * Resets the in-memory rate limit store (useful for tests).
 */
export function resetRateLimits(): void {
  rateLimitStore.clear();
}
