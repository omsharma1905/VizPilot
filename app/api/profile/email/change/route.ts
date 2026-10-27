import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/src/lib/auth/session';
import { getUsersCollection } from '@/src/lib/db/collections';
import { verifyPassword } from '@/src/lib/auth/password';
import { issueVerificationCode, VERIFICATION_EXPIRATION_MINUTES } from '@/src/lib/email/verification';
import { getEmailProvider } from '@/src/lib/email/provider';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import { checkRateLimit, getClientIp, rateLimitResponse } from '@/src/lib/security/rate-limit';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const NO_STORE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '0',
};

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(request: NextRequest) {
  try {
    const csrfError = assertCsrfSafe(request);
    if (csrfError) return csrfError;

    const auth = await getAuthenticatedUser(request);
    if (!auth) {
      return NextResponse.json(
        { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be signed in to request an email change.' } },
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
    const { newEmail, currentPassword } = body || {};

    if (!newEmail || typeof newEmail !== 'string' || !EMAIL_REGEX.test(newEmail.trim())) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_EMAIL', message: 'Please provide a valid corporate email address.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    if (!currentPassword || typeof currentPassword !== 'string') {
      return NextResponse.json(
        { success: false, error: { code: 'PASSWORD_REQUIRED', message: 'Current password is required to change your email.' } },
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

    // Authenticate sensitive operation with current password
    const isPasswordValid = await verifyPassword(currentPassword, userDoc.passwordHash);
    if (!isPasswordValid) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_PASSWORD', message: 'Current password is incorrect.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    const cleanNewEmail = newEmail.trim();
    const newEmailNormalized = cleanNewEmail.toLowerCase();

    if (newEmailNormalized === userDoc.emailNormalized) {
      return NextResponse.json(
        { success: false, error: { code: 'SAME_EMAIL', message: 'New email must be different from your current email address.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    // Check if new email is already claimed by another user
    const existing = await usersCol.findOne({
      emailNormalized: newEmailNormalized,
      id: { $ne: auth.user.id },
    });

    if (existing) {
      return NextResponse.json(
        { success: false, error: { code: 'EMAIL_UNAVAILABLE', message: 'Unable to use this email address. Please choose another.' } },
        { status: 409, headers: NO_STORE_HEADERS }
      );
    }

    let code: string;
    try {
      const issued = await issueVerificationCode({
        userId: auth.user.id,
        email: userDoc.email,
        purpose: 'email_change',
        targetEmail: cleanNewEmail,
      });
      code = issued.code;
    } catch (issueErr) {
      const msg = issueErr instanceof Error ? issueErr.message : 'Cooldown active.';
      return NextResponse.json(
        { success: false, error: { code: 'COOLDOWN_ACTIVE', message: msg } },
        { status: 429, headers: NO_STORE_HEADERS }
      );
    }

    // Send code to the NEW email address
    const emailProvider = getEmailProvider();
    const delivery = await emailProvider.sendVerificationEmail({
      to: cleanNewEmail,
      name: userDoc.name,
      code,
      expiresInMinutes: VERIFICATION_EXPIRATION_MINUTES,
      purpose: 'email_change',
    });

    if (!delivery.success) {
      return NextResponse.json(
        { success: false, error: { code: 'DELIVERY_FAILED', message: delivery.error || 'Failed to dispatch verification email to the new address.' } },
        { status: 502, headers: NO_STORE_HEADERS }
      );
    }

    return NextResponse.json(
      {
        success: true,
        message: `Verification code sent to ${cleanNewEmail}. Your account email will remain unchanged until this code is confirmed.`,
        targetEmail: cleanNewEmail,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    console.error('[VizPilot Profile] Email change request error:', err);
    return NextResponse.json(
      { success: false, error: { code: 'EMAIL_CHANGE_FAILED', message: 'An unexpected error occurred during email change request.' } },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
