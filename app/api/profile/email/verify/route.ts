import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/src/lib/auth/session';
import { getUsersCollection } from '@/src/lib/db/collections';
import { verifyCode } from '@/src/lib/email/verification';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import type { SafeUser } from '@/src/types/auth';

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
        { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be signed in to verify your email.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    const contentType = request.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CONTENT_TYPE', message: 'Content-Type must be application/json.' } },
        { status: 415, headers: NO_STORE_HEADERS }
      );
    }

    const body = await request.json();
    const { code } = body || {};

    if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code.trim())) {
      return NextResponse.json(
        { success: false, error: { code: 'VALIDATION_ERROR', message: 'Please enter a valid 6-digit numeric verification code.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const verificationResult = await verifyCode({
      userId: auth.user.id,
      code: code.trim(),
      purpose: 'signup_verification',
    });

    if (!verificationResult.success) {
      return NextResponse.json(
        { success: false, error: { code: 'VERIFICATION_FAILED', message: verificationResult.error || 'Verification failed.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const now = new Date();
    const usersCol = await getUsersCollection();
    await usersCol.updateOne(
      { id: auth.user.id },
      {
        $set: {
          emailVerifiedAt: now,
          updatedAt: now,
        },
      }
    );

    const updatedUser: SafeUser = {
      ...auth.user,
      emailVerifiedAt: now.toISOString(),
    };

    return NextResponse.json(
      {
        success: true,
        message: 'Email verified successfully.',
        user: updatedUser,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    console.error('[VizPilot Profile] Email verification error:', err);
    return NextResponse.json(
      { success: false, error: { code: 'VERIFICATION_ERROR', message: 'An unexpected error occurred during verification.' } },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
