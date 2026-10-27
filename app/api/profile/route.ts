import { NextRequest, NextResponse } from 'next/server';
import { getAuthenticatedUser } from '@/src/lib/auth/session';
import { getUsersCollection } from '@/src/lib/db/collections';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import type { SafeUser } from '@/src/types/auth';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const NO_STORE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '0',
};

export async function GET(request: NextRequest) {
  try {
    const auth = await getAuthenticatedUser(request);
    if (!auth) {
      return NextResponse.json(
        { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be signed in to view your profile.' } },
        { status: 401, headers: NO_STORE_HEADERS }
      );
    }

    return NextResponse.json(
      {
        success: true,
        user: auth.user,
        workspace: auth.workspace,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    console.error('[VizPilot Profile] GET profile error:', err);
    return NextResponse.json(
      { success: false, error: { code: 'PROFILE_ERROR', message: 'Failed to retrieve profile.' } },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const csrfError = assertCsrfSafe(request);
    if (csrfError) return csrfError;

    const auth = await getAuthenticatedUser(request);
    if (!auth) {
      return NextResponse.json(
        { success: false, error: { code: 'UNAUTHORIZED', message: 'You must be signed in to update your profile.' } },
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
    const { name } = body || {};

    if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 60) {
      return NextResponse.json(
        { success: false, error: { code: 'VALIDATION_ERROR', message: 'Full name must be between 2 and 60 characters.' } },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const cleanName = name.trim();
    const now = new Date();
    const usersCol = await getUsersCollection();

    await usersCol.updateOne(
      { id: auth.user.id },
      {
        $set: {
          name: cleanName,
          updatedAt: now,
        },
      }
    );

    const updatedUser: SafeUser = {
      ...auth.user,
      name: cleanName,
    };

    return NextResponse.json(
      {
        success: true,
        message: 'Your name has been updated.',
        user: updatedUser,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    console.error('[VizPilot Profile] PATCH profile error:', err);
    return NextResponse.json(
      { success: false, error: { code: 'UPDATE_FAILED', message: 'Failed to update profile.' } },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
