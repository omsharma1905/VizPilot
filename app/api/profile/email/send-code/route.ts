import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/src/lib/auth/session';
import { issueVerificationCode, VERIFICATION_EXPIRATION_MINUTES } from '@/src/lib/email/verification';
import { getEmailProvider } from '@/src/lib/email/provider';
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

    const auth = await getAuthenticatedUser(request);
    if (!auth) {
      return NextResponse.json(
        { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be signed in to request a verification code.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    if (auth.user.emailVerifiedAt) {
      return NextResponse.json(
        { success: false, error: { code: 'ALREADY_VERIFIED', message: 'Your email address is already verified.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    let code: string;
    try {
      const issued = await issueVerificationCode({
        userId: auth.user.id,
        email: auth.user.email,
        purpose: 'signup_verification',
      });
      code = issued.code;
    } catch (issueErr) {
      const msg = issueErr instanceof Error ? issueErr.message : 'Cooldown active.';
      return NextResponse.json(
        { success: false, error: { code: 'COOLDOWN_ACTIVE', message: msg } },
        { status: 429, headers: NO_STORE_HEADERS }
      );
    }

    const emailProvider = getEmailProvider();
    const delivery = await emailProvider.sendVerificationEmail({
      to: auth.user.email,
      name: auth.user.name,
      code,
      expiresInMinutes: VERIFICATION_EXPIRATION_MINUTES,
      purpose: 'signup_verification',
    });

    if (!delivery.success) {
      return NextResponse.json(
        { success: false, error: { code: 'DELIVERY_FAILED', message: delivery.error || 'Failed to dispatch verification email.' } },
        { status: 502, headers: NO_STORE_HEADERS }
      );
    }

    return NextResponse.json(
      {
        success: true,
        message: `Verification code sent to ${auth.user.email}.`,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    console.error('[VizPilot Profile] Send code error:', err);
    return NextResponse.json(
      { success: false, error: { code: 'SEND_CODE_FAILED', message: 'An unexpected error occurred while requesting verification code.' } },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
