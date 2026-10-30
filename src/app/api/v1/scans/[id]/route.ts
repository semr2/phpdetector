import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import type { ScanSummary } from '@/lib/domain/types';
import { normalizePhpDetection } from '@/lib/domain/php-detection';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** GET /api/v1/scans/{id} — scan lifecycle state & progress (SRS §8). */
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  const scan = await db.scan.findUnique({
    where: { id },
    include: {
      _count: { select: { findings: true, features: true, pages: true } },
    },
  });

  if (!scan || scan.mode !== 'live') {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  let summary: ScanSummary | null = null;
  if (scan.summary) {
    try {
      summary = JSON.parse(scan.summary) as ScanSummary;
    } catch {
      summary = null;
    }
  }

  let storedPhp: unknown = null;
  if (scan.phpEvidence) {
    try {
      storedPhp = JSON.parse(scan.phpEvidence);
    } catch {
      storedPhp = null;
    }
  }
  const phpEvidence = normalizePhpDetection(storedPhp, scan.phpDetection, scan.phpFramework);

  return NextResponse.json({
    id: scan.id,
    targetUrl: scan.targetUrl,
    mode: scan.mode,
    status: scan.status,
    progress: scan.progress,
    currentStep: scan.currentStep,
    phpDetection: scan.phpDetection,
    phpFramework: scan.phpFramework,
    phpEvidence,
    summary,
    error: scan.error,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    createdAt: scan.createdAt,
    counts: {
      findings: scan._count.findings,
      features: scan._count.features,
      pages: scan._count.pages,
    },
  });
}
