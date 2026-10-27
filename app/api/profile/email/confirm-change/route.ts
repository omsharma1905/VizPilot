import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/src/lib/auth/session';
import { getUsersCollection } from '@/src/lib/db/collections';
import { verifyCode } from '@/src/lib/email/verification';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import { checkRateLimit, getClientIp, rateLimitResponse } from '@/src/lib/security/rate-limit';
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
        { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be signed in to confirm an email change.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    const ip = getClientIp(request);
    const rateLimit = checkRateLimit('email_verification', `${auth.user.id}:${ip}`);
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
      purpose: 'email_change',
    });

    if (!verificationResult.success || !verificationResult.verification) {
      return NextResponse.json(
        { success: false, error: { code: 'VERIFICATION_FAILED', message: verificationResult.error || 'Email change verification failed.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const targetEmail = verificationResult.verification.targetEmail;
    const targetEmailNormalized = verificationResult.verification.targetEmailNormalized;

    if (!targetEmail || !targetEmailNormalized) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_VERIFICATION_RECORD', message: 'Target email data is missing from verification record.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const usersCol = await getUsersCollection();

    // Check if target email was claimed in the interim
    const conflict = await usersCol.findOne({
      emailNormalized: targetEmailNormalized,
      id: { $ne: auth.user.id },
    });

    if (conflict) {
      return NextResponse.json(
        { success: false, error: { code: 'EMAIL_UNAVAILABLE', message: 'Unable to use this email address. Please choose another.' } },
        { status: 409, headers: NO_STORE_HEADERS }
      );
    }

    const now = new Date();

    // Promote new email to account email and mark verified
    await usersCol.updateOne(
      { id: auth.user.id },
      {
        $set: {
          email: targetEmail,
          emailNormalized: targetEmailNormalized,
          emailVerifiedAt: now,
          updatedAt: now,
        },
      }
    );

    const updatedUser: SafeUser = {
      ...auth.user,
      email: targetEmail,
      emailVerifiedAt: now.toISOString(),
    };

    return NextResponse.json(
      {
        success: true,
        message: 'Your email address has been successfully updated and verified.',
        user: updatedUser,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    console.error('[VizPilot Profile] Confirm email change error:', err);
    return NextResponse.json(
      { success: false, error: { code: 'CONFIRM_CHANGE_FAILED', message: 'An unexpected error occurred while confirming email change.' } },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
