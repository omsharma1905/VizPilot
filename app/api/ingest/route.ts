import { NextRequest, NextResponse } from 'next/server';
import { ingestFile, IngestionError } from '@/src/lib/ingestion';
import { createProcessingContext, getElapsedMs } from '@/src/lib/security/context';
import { safeTelemetryLogger } from '@/src/lib/security/telemetry';
import { getAuthenticatedUser } from '@/src/lib/auth/session';
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
  const csrfError = assertCsrfSafe(request);
  if (csrfError) return csrfError;

  const ip = getClientIp(request);
  const rateLimit = checkRateLimit('ingest', ip);
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

    const formData = await request.formData();
    const file = formData.get('file');
    const rawMode = formData.get('mode') || rawModeHeader;

    // Update context with validated form mode while preserving user context
    const currentUserId = ctx.userId;
    const currentWorkspaceId = ctx.workspaceId;
    ctx = createProcessingContext(request, rawMode);
    ctx.userId = currentUserId;
    ctx.workspaceId = currentWorkspaceId;

    if (!file || !(file instanceof Blob)) {
      safeTelemetryLogger.log({
        requestId: ctx.requestId,
        mode: ctx.mode,
        stage: 'ingest',
        durationMs: getElapsedMs(ctx),
        success: false,
        errorCode: 'INVALID_FILE',
      });

      return NextResponse.json(
        {
          success: false,
          error: {
            code: 'INVALID_FILE',
            message: 'No file was provided in the multipart/form-data request payload.',
            recoverable: false,
          },
        },
        { status: 400, headers: NO_STORE_HEADERS }
      );
    }

    const fileName = (file as { name?: string }).name || 'uploaded_data';
    const fileSize = file.size;
    const mimeType = file.type || '';

    // Convert file to Buffer in memory (never written to disk)
    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Ingest through pipeline
    const dataset = await ingestFile({
      fileName,
      fileSize,
      mimeType,
      mode: ctx.mode,
      buffer,
    });

    const durationMs = getElapsedMs(ctx);
    const table = dataset.tables[0];

    safeTelemetryLogger.log({
      requestId: ctx.requestId,
      mode: ctx.mode,
      stage: 'ingest',
      durationMs,
      success: true,
      fileType: dataset.source.fileType,
      fileSize: dataset.source.fileSize,
      rowCount: table?.rowCount,
      columnCount: table?.columnCount,
    });

    return NextResponse.json(
      {
        success: true,
        dataset,
        requestId: ctx.requestId,
      },
      { status: 200, headers: NO_STORE_HEADERS }
    );
  } catch (err) {
    const durationMs = getElapsedMs(ctx);

    if (err instanceof IngestionError) {
      safeTelemetryLogger.log({
        requestId: ctx.requestId,
        mode: ctx.mode,
        stage: 'ingest',
        durationMs,
        success: false,
        errorCode: err.code,
      });

      return NextResponse.json(
        {
          success: false,
          error: err.toResponse(),
          requestId: ctx.requestId,
        },
        { status: err.statusCode, headers: NO_STORE_HEADERS }
      );
    }

    // Safeguard: Never expose internal server stack traces to client
    const errorMessage = err instanceof Error ? err.message : 'An unexpected error occurred during data ingestion.';
    safeTelemetryLogger.log({
      requestId: ctx.requestId,
      mode: ctx.mode,
      stage: 'ingest',
      durationMs,
      success: false,
      errorCode: 'PARSE_FAILED',
    });

    return NextResponse.json(
      {
        success: false,
        error: {
          code: 'PARSE_FAILED',
          message: errorMessage,
          recoverable: true,
        },
        requestId: ctx.requestId,
      },
      { status: 500, headers: NO_STORE_HEADERS }
    );
  }
}
