import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { createLogger } from '@/lib/core/logger';
import { validateTargetUrl, UrlValidationError } from '@/lib/core/url-validation';
import { assertHostInScope, ScopeViolationError } from '@/lib/core/network-scope';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const log = createLogger('api:scans');

const CreateScanSchema = z.object({
  url: z.string().min(1).max(2048),
  demo: z.boolean().optional().default(false),
});

/** GET /api/v1/scans — list recent scans with summary counts. */
export async function GET() {
  const [{ db }, { recoverStaleScans }] = await Promise.all([
    import('@/lib/db'),
    import('@/lib/services/scan-orchestrator'),
  ]);
  await recoverStaleScans();
  const scans = await db.scan.findMany({
    where: { mode: 'live' },
    orderBy: { createdAt: 'desc' },
    take: 50,
    select: {
      id: true,
      targetUrl: true,
      mode: true,
      status: true,
      progress: true,
      currentStep: true,
      phpDetection: true,
      error: true,
      createdAt: true,
      completedAt: true,
      _count: { select: { findings: true, features: true, pages: true } },
    },
  });

  return NextResponse.json({
    scans: scans.map((s) => ({
      id: s.id,
      targetUrl: s.targetUrl,
      mode: s.mode,
      status: s.status,
      progress: s.progress,
      currentStep: s.currentStep,
      phpDetection: s.phpDetection,
      error: s.error,
      createdAt: s.createdAt,
      completedAt: s.completedAt,
      counts: {
        findings: s._count.findings,
        features: s._count.features,
        pages: s._count.pages,
      },
    })),
  });
}

/**
 * POST /api/v1/scans — initiate a new scan (SRS §8).
 * Pipeline steps 1–3 run synchronously here: validate URL, verify network
 * scope, persist the queued record — then the orchestrator continues in the
 * background and the client polls GET /api/v1/scans/{id}.
 */
export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const parsed = CreateScanSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message ?? 'Invalid request' },
      { status: 400 },
    );
  }

  const { url, demo } = parsed.data;

  if (demo) {
    return NextResponse.json(
      { error: 'Demo fixtures are read-only and separate from live scans. Open the dedicated demo dashboard instead.' },
      { status: 400 },
    );
  }

  // Pipeline step 1 — API request validation (backend independently rejects).
  let normalizedUrl: string;
  let host: string;
  try {
    const target = validateTargetUrl(url);
    normalizedUrl = target.url;
    host = target.host;
  } catch (error) {
    if (error instanceof UrlValidationError) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }
    return NextResponse.json({ error: 'Invalid target URL' }, { status: 400 });
  }

  // Pipeline step 2 — network scope check BEFORE scan record init (fail fast).
  try {
    await assertHostInScope(host);
  } catch (error) {
    const message =
      error instanceof ScopeViolationError
        ? error.message
        : 'Network scope verification failed';
    log.warn('scan rejected by scope policy', { url: normalizedUrl, reason: message });
    return NextResponse.json({ error: message }, { status: 403 });
  }

  // Pipeline step 3 — scan record initialization.
  const [{ db }, { launchScan }] = await Promise.all([
    import('@/lib/db'),
    import('@/lib/services/scan-orchestrator'),
  ]);
  const scan = await db.scan.create({
    data: {
      targetUrl: normalizedUrl,
      mode: 'live',
      status: 'queued',
      currentStep: 0,
      progress: 0,
    },
  });

  log.info('scan queued', { scanId: scan.id, url: normalizedUrl, mode: 'live' });

  // Continue pipeline steps 4–12 in the background.
  launchScan(scan.id, normalizedUrl);

  return NextResponse.json({ id: scan.id, status: scan.status }, { status: 201 });
}
