import { NextRequest, NextResponse } from 'next/server';
import { clearSessionCookie, destroySession, SESSION_COOKIE_NAME } from '@/src/lib/auth/session';
import { assertCsrfSafe } from '@/src/lib/security/csrf';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const NO_STORE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '0',
};

export async function POST(request: NextRequest) {
  try {
    const csrfError = assertCsrfSafe(request);
    if (csrfError) return csrfError;

    const token = request.cookies.get(SESSION_COOKIE_NAME)?.value;
    if (token) {
      await destroySession(token);
    }

    const res = NextResponse.json(
      { success: true },
      { status: 200, headers: NO_STORE_HEADERS }
    );

    clearSessionCookie(res);
    return res;
  } catch (err) {
    console.error('[VizPilot Auth] Logout error:', err);
    const res = NextResponse.json(
      { success: true },
      { status: 200, headers: NO_STORE_HEADERS }
    );
    clearSessionCookie(res);
    return res;
  }
}
