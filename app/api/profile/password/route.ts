import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser, SESSION_COOKIE_NAME } from '@/src/lib/auth/session';
import { getUsersCollection, getSessionsCollection } from '@/src/lib/db/collections';
import { verifyPassword, hashPassword } from '@/src/lib/auth/password';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import { checkRateLimit, getClientIp, rateLimitResponse } from '@/src/lib/security/rate-limit';

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

    const auth = await getAuthenticatedUser(request);
    if (!auth) {
      return NextResponse.json(
        { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be signed in to change your password.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    const ip = getClientIp(request);
    const rateLimit = checkRateLimit('password', `${auth.user.id}:${ip}`);
    if (!rateLimit.allowed) {
      return rateLimitResponse(rateLimit);
    }

    const contentType = request.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CONTENT_TYPE', message: 'Content-Type must be application/json.' } },
        { status: 415, headers: NO_STORE_HEADERS }
      );
    }

    const body = await request.json();
    const { currentPassword, newPassword, confirmPassword } = body || {};

    if (!currentPassword || typeof currentPassword !== 'string') {
      return NextResponse.json(
        { success: false, error: { code: 'CURRENT_PASSWORD_REQUIRED', message: 'Please enter your current password.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_NEW_PASSWORD', message: 'New password must contain at least 8 characters.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    if (newPassword !== confirmPassword) {
      return NextResponse.json(
        { success: false, error: { code: 'PASSWORD_MISMATCH', message: 'New password and confirmation do not match.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const usersCol = await getUsersCollection();
    const userDoc = await usersCol.findOne({ id: auth.user.id });

    if (!userDoc) {
      return NextResponse.json(
        { success: false, error: { code: 'USER_NOT_FOUND', message: 'User record not found.' } },
        { status: 404, headers: NO_STORE_HEADERS }
      );
    }

    const isCurrentValid = await verifyPassword(currentPassword, userDoc.passwordHash);
    if (!isCurrentValid) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CURRENT_PASSWORD', message: 'Current password is incorrect.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    const isIdentical = await verifyPassword(newPassword, userDoc.passwordHash);
    if (isIdentical) {
      return NextResponse.json(
        { success: false, error: { code: 'IDENTICAL_PASSWORD', message: 'New password must be different from your current password.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const newHash = await hashPassword(newPassword);
    const now = new Date();

    await usersCol.updateOne(
      { id: auth.user.id },
      {
        $set: {
          passwordHash: newHash,
          updatedAt: now,
        },
      }
    );

    // Invalidate all other active sessions for security while retaining current session
    try {
      const cookieHeader = request.headers.get('cookie') || '';
      const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE_NAME}=([^;]+)`));
      const currentToken = match ? decodeURIComponent(match[1]) : undefined;

      if (currentToken) {
        const sessionsCol = await getSessionsCollection();
        await sessionsCol.deleteMany({
          userId: auth.user.id,
          token: { $ne: currentToken },
        });
      }
    } catch (sessionErr) {
      console.warn('[VizPilot Profile] Session purge warning:', sessionErr);
    }

    return NextResponse.json(
      {
        success: true,
        message: 'Password changed successfully. All other active sessions have been signed out.',
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    console.error('[VizPilot Profile] Change password error:', err);
    return NextResponse.json(
      { success: false, error: { code: 'PASSWORD_CHANGE_FAILED', message: 'An unexpected error occurred while changing password.' } },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
