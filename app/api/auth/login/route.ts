import { NextRequest, NextResponse } from 'next/server';
import { getUsersCollection, getWorkspacesCollection } from '@/src/lib/db/collections';
import { verifyPassword } from '@/src/lib/auth/password';
import { createSession, setSessionCookie } from '@/src/lib/auth/session';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import { checkRateLimit, getClientIp, rateLimitResponse } from '@/src/lib/security/rate-limit';
import type { SafeUser, SafeWorkspace } from '@/src/types/auth';

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

    const ip = getClientIp(request);
    const rateLimit = checkRateLimit('login', ip);
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
    const { email, password } = body || {};

    if (!email || typeof email !== 'string' || !password || typeof password !== 'string') {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CREDENTIALS', message: 'Please provide both email and password.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const emailNormalized = email.trim().toLowerCase();
    const usersCol = await getUsersCollection();
    const userDoc = await usersCol.findOne({ emailNormalized });

    if (!userDoc) {
      // Security: use generic error message to prevent account enumeration
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    const isValidPassword = await verifyPassword(password, userDoc.passwordHash);
    if (!isValidPassword) {
      return NextResponse.json(
        { success: false, error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    const workspacesCol = await getWorkspacesCollection();
    let workspaceDoc = await workspacesCol.findOne({ id: userDoc.defaultWorkspaceId });
    if (!workspaceDoc) {
      workspaceDoc = await workspacesCol.findOne({ ownerUserId: userDoc.id });
    }

    const safeUser: SafeUser = {
      id: userDoc.id,
      name: userDoc.name,
      email: userDoc.email,
      defaultWorkspaceId: userDoc.defaultWorkspaceId,
      emailVerifiedAt: userDoc.emailVerifiedAt ? (userDoc.emailVerifiedAt instanceof Date ? userDoc.emailVerifiedAt.toISOString() : userDoc.emailVerifiedAt) : null,
      createdAt: userDoc.createdAt,
    };

    const safeWorkspace: SafeWorkspace = {
      id: workspaceDoc?.id || userDoc.defaultWorkspaceId,
      name: workspaceDoc?.name || `${userDoc.name}'s Workspace`,
      ownerUserId: userDoc.id,
      createdAt: workspaceDoc?.createdAt || userDoc.createdAt,
    };

    const userAgent = request.headers.get('user-agent') || undefined;
    const sessionToken = await createSession(userDoc.id, { userAgent, ip });

    const res = NextResponse.json(
      {
        success: true,
        user: safeUser,
        workspace: safeWorkspace,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );

    setSessionCookie(res, sessionToken);
    return res;
  } catch (err) {
    console.error('[VizPilot Auth] Login error:', err);
    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'LOGIN_FAILED',
          message: err instanceof Error ? err.message : 'An unexpected error occurred during login.',
        },
      },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
