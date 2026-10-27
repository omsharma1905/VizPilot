import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { getUsersCollection, getWorkspacesCollection } from '@/src/lib/db/collections';
import { initializeDatabaseIndexes } from '@/src/lib/db/init';
import { hashPassword } from '@/src/lib/auth/password';
import { createSession, setSessionCookie } from '@/src/lib/auth/session';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import { checkRateLimit, getClientIp, rateLimitResponse } from '@/src/lib/security/rate-limit';
import type { UserDocument, WorkspaceDocument, SafeUser, SafeWorkspace } from '@/src/types/auth';

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

    const ip = getClientIp(request);
    const rateLimit = checkRateLimit('signup', ip);
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
    const { name, email, password } = body || {};

    if (!name || typeof name !== 'string' || name.trim().length < 2) {
      return NextResponse.json(
        { success: false, error: { code: 'VALIDATION_ERROR', message: 'Full name must be at least 2 characters.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    if (!email || typeof email !== 'string' || !EMAIL_REGEX.test(email.trim())) {
      return NextResponse.json(
        { success: false, error: { code: 'VALIDATION_ERROR', message: 'Please provide a valid email address.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return NextResponse.json(
        { success: false, error: { code: 'VALIDATION_ERROR', message: 'Password must be at least 8 characters long.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    // Ensure database indexes
    await initializeDatabaseIndexes();

    const emailNormalized = email.trim().toLowerCase();
    const usersCol = await getUsersCollection();

    // Check for existing account
    const existingUser = await usersCol.findOne({ emailNormalized });
    if (existingUser) {
      return NextResponse.json(
        { success: false, error: { code: 'EMAIL_ALREADY_EXISTS', message: 'An account with this email already exists.' } },
        { status: 409, headers: NO_STORE_HEADERS }
      );
    }

    const passwordHash = await hashPassword(password);
    const userId = `user_${crypto.randomUUID()}`;
    const workspaceId = `ws_${crypto.randomUUID()}`;
    const now = new Date();

    const workspacesCol = await getWorkspacesCollection();
    const workspaceDoc: WorkspaceDocument = {
      id: workspaceId,
      name: `${name.trim()}'s Workspace`,
      ownerUserId: userId,
      createdAt: now,
      updatedAt: now,
    };
    await workspacesCol.insertOne(workspaceDoc);

    const userDoc: UserDocument = {
      id: userId,
      name: name.trim(),
      email: email.trim(),
      emailNormalized,
      passwordHash,
      defaultWorkspaceId: workspaceId,
      emailVerifiedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    await usersCol.insertOne(userDoc);

    // Generate initial verification code and send email
    try {
      const { issueVerificationCode, VERIFICATION_EXPIRATION_MINUTES } = await import('@/src/lib/email/verification');
      const { getEmailProvider } = await import('@/src/lib/email/provider');
      const { code } = await issueVerificationCode({
        userId,
        email: userDoc.email,
        purpose: 'signup_verification',
      });
      const emailProvider = getEmailProvider();
      await emailProvider.sendVerificationEmail({
        to: userDoc.email,
        name: userDoc.name,
        code,
        expiresInMinutes: VERIFICATION_EXPIRATION_MINUTES,
        purpose: 'signup_verification',
      });
    } catch (emailErr) {
      console.warn('[VizPilot Auth] Initial verification email delivery warning:', emailErr);
    }

    const userAgent = request.headers.get('user-agent') || undefined;
    const sessionToken = await createSession(userId, { userAgent, ip });

    const safeUser: SafeUser = {
      id: userId,
      name: userDoc.name,
      email: userDoc.email,
      defaultWorkspaceId: workspaceId,
      emailVerifiedAt: null,
      createdAt: now,
    };

    const safeWorkspace: SafeWorkspace = {
      id: workspaceId,
      name: workspaceDoc.name,
      ownerUserId: userId,
      createdAt: now,
    };

    const res = NextResponse.json(
      {
        success: true,
        user: safeUser,
        workspace: safeWorkspace,
      },
      { status: 201, headers: NO_STORE_HEADERS }
    );

    setSessionCookie(res, sessionToken);
    return res;
  } catch (err) {
    console.error('[VizPilot Auth] Signup error:', err);
    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'SIGNUP_FAILED',
          message: err instanceof Error ? err.message : 'An unexpected error occurred during signup.',
        },
      },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
