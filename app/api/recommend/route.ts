/**
 * POST /api/recommend — Phase 2C & Phase 2E
 *
 * Server-side endpoint generating structured visualization recommendations
 * from a VizPilotDataProfile or VizPilotDataset.
 *
 * ZERO-TRACE:
 * - Executes in-memory without persistent logging of profile/dataset contents.
 * - Emits only safe metadata telemetry via safeTelemetryLogger.
 * - Enforces no-store caching headers.
 */

import { NextRequest, NextResponse } from 'next/server';
import type { VizPilotDataProfile } from '@/src/types/profiling';
import type { VizPilotDataset } from '@/src/types/dataset';
import { profileDataset } from '@/src/lib/profiling';
import { getVisualizationRecommendation } from '@/src/lib/ai/recommendation';
import { createProcessingContext, getElapsedMs } from '@/src/lib/security/context';
import { safeTelemetryLogger } from '@/src/lib/security/telemetry';
import { getAuthenticatedUser } from '@/src/lib/auth/session';
import { assertCsrfSafe } from '@/src/lib/security/csrf';
import { checkRateLimit, getClientIp, rateLimitResponse } from '@/src/lib/security/rate-limit';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

const NO_STORE_HEADERS = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
  'Pragma': 'no-cache',
  'Expires': '0',
};

export async function POST(request: NextRequest) {
  const csrfError = assertCsrfSafe(request);
  if (csrfError) return csrfError;

  const ip = getClientIp(request);
  const rateLimit = checkRateLimit('recommend', ip);
  if (!rateLimit.allowed) {
    return rateLimitResponse(rateLimit);
  }

  const rawModeHeader = request.headers.get('x-vizpilot-mode');
  let ctx = createProcessingContext(request, rawModeHeader);

  try {
    const auth = await getAuthenticatedUser(request);
    if (auth) {
      ctx.userId = auth.user.id;
      ctx.workspaceId = auth.workspace.id;
    }

    const contentType = request.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_CONTENT_TYPE',
            message: 'Content-Type must be application/json.',
          },
        },
        { status: 415, headers: NO_STORE_HEADERS }
      );
    }

    const body = await request.json();
    const mode = body.mode || rawModeHeader;
    const currentUserId = ctx.userId;
    const currentWorkspaceId = ctx.workspaceId;
    ctx = createProcessingContext(request, mode);
    ctx.userId = currentUserId;
    ctx.workspaceId = currentWorkspaceId;

    let profile: VizPilotDataProfile | undefined = body.profile;

    // If a dataset was provided instead of a profile, profile it first
    if (!profile && body.dataset) {
      const dataset = body.dataset as VizPilotDataset;
      profile = profileDataset(dataset);
    }

    if (!profile || typeof profile !== 'object' || !Array.isArray(profile.tables)) {
      safeTelemetryLogger.log({
        requestId: ctx.requestId,
        mode: ctx.mode,
        stage: 'recommend',
        durationMs: getElapsedMs(ctx),
        success: false,
        errorCode: 'INVALID_PAYLOAD',
      });

      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_PAYLOAD',
            message: 'A valid VizPilotDataProfile or VizPilotDataset is required.',
          },
          requestId: ctx.requestId,
        },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    // Generate recommendation
    const recommendation = await getVisualizationRecommendation(profile);
    const durationMs = getElapsedMs(ctx);

    safeTelemetryLogger.log({
      requestId: ctx.requestId,
      mode: ctx.mode,
      stage: 'recommend',
      durationMs,
      success: true,
      provider: recommendation.providerUsed || 'none',
      model: recommendation.modelUsed || 'none',
      fallbackUsed: recommendation.fallbackUsed,
      candidateCount: recommendation.alternatives.length + 1,
      chartType: recommendation.primary.chartType,
    });

    return NextResponse.json(
      {
        success: true,
        recommendation,
        requestId: ctx.requestId,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    const durationMs = getElapsedMs(ctx);
    const errorMessage = err instanceof Error ? err.message : 'Unknown recommendation error';

    safeTelemetryLogger.log({
      requestId: ctx.requestId,
      mode: ctx.mode,
      stage: 'recommend',
      durationMs,
      success: false,
      errorCode: 'RECOMMENDATION_FAILED',
    });

    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'RECOMMENDATION_FAILED',
          message: errorMessage,
        },
        requestId: ctx.requestId,
      },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
