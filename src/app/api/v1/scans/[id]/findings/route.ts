import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import type { Evidence } from '@/lib/domain/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const STATUSES = ['confirmed', 'potential', 'inconclusive'] as const;

/**
 * GET /api/v1/scans/{id}/findings — paginated findings with filters (SRS §8).
 * Query params: severity, status, page (1-based), pageSize (default 20, max 100).
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  const scan = await db.scan.findUnique({ where: { id }, select: { id: true } });
  if (!scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const url = new URL(request.url);
  const severity = url.searchParams.get('severity');
  const status = url.searchParams.get('status');
  const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
  const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get('pageSize') ?? '20') || 20));

  const where: { scanId: string; severity?: string; status?: string } = { scanId: id };
  if (severity && (SEVERITIES as readonly string[]).includes(severity)) {
    where.severity = severity;
  }
  if (status && (STATUSES as readonly string[]).includes(status)) {
    where.status = status;
  }

  const [total, rows] = await Promise.all([
    db.finding.count({ where }),
    db.finding.findMany({
      where,
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
  ]);

  // Order findings by severity rank (critical first) rather than alphabetical.
  const rank: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  rows.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));

  return NextResponse.json({
    total,
    page,
    pageSize,
    findings: rows.map((f) => {
      let evidence: Evidence[] = [];
      try {
        evidence = JSON.parse(f.evidence) as Evidence[];
      } catch {
        evidence = [];
      }
      return {
        id: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        status: f.status,
        affectedUrl: f.affectedUrl,
        evidence,
        remediation: f.remediation,
      };
    }),
  });
}
