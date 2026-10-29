import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import type { Evidence, FindingRecord, FeatureRecord, PhpDetectionResult, ScanSummary } from '@/lib/domain/types';
import { buildReportHtml, buildReportJson, type ReportInput } from '@/lib/services/report';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * GET /api/v1/scans/{id}/report?format=json|html (SRS §8).
 *  - json: canonical machine-readable report (download)
 *  - html: standalone escaped document (view online or print-to-PDF)
 * Query: download=1 forces Content-Disposition: attachment.
 */
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const url = new URL(request.url);
  const format = (url.searchParams.get('format') ?? 'json').toLowerCase();
  const download = url.searchParams.get('download') === '1';

  const scan = await db.scan.findUnique({
    where: { id },
    include: { findings: true, features: true, pages: true },
  });
  if (!scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  let php: PhpDetectionResult;
  try {
    const evidence = scan.phpEvidence ? (JSON.parse(scan.phpEvidence) as Evidence[]) : [];
    php = {
      result: (scan.phpDetection ?? 'inconclusive') as PhpDetectionResult['result'],
      framework: scan.phpFramework ?? undefined,
      evidence,
      indicators: [],
    };
  } catch {
    php = { result: 'inconclusive', evidence: [], indicators: [] };
  }

  let summary: ScanSummary = {
    pagesCrawled: scan.pages.length,
    featuresTotal: scan.features.length,
    findingsTotal: scan.findings.length,
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    findingsByStatus: { confirmed: 0, potential: 0, inconclusive: 0 },
  };
  if (scan.summary) {
    try {
      summary = JSON.parse(scan.summary) as ScanSummary;
    } catch {
      /* keep default */
    }
  }

  const findings: FindingRecord[] = scan.findings.map((f) => {
    let evidence: Evidence[] = [];
    try {
      evidence = JSON.parse(f.evidence) as Evidence[];
    } catch {
      evidence = [];
    }
    return {
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity as FindingRecord['severity'],
      confidence: f.confidence as FindingRecord['confidence'],
      status: f.status as FindingRecord['status'],
      affectedUrl: f.affectedUrl,
      evidence,
      remediation: f.remediation,
    };
  });

  const features: FeatureRecord[] = scan.features.map((f) => {
    let details: Record<string, unknown> | undefined;
    if (f.details) {
      try {
        details = JSON.parse(f.details) as Record<string, unknown>;
      } catch {
        details = undefined;
      }
    }
    return {
      kind: f.kind as FeatureRecord['kind'],
      name: f.name,
      location: f.location,
      details,
    };
  });

  const input: ReportInput = {
    id: scan.id,
    targetUrl: scan.targetUrl,
    mode: scan.mode === 'demo' ? 'demo' : 'live',
    status: scan.status,
    createdAt: scan.createdAt.toISOString(),
    completedAt: scan.completedAt?.toISOString(),
    php: {
      result: php.result,
      framework: php.framework,
      version: php.version,
      evidence: php.evidence,
      indicators: php.indicators,
    },
    summary,
    pages: scan.pages.map((p) => ({ url: p.url, httpStatus: p.httpStatus ?? 0, depth: p.depth })),
    features,
    findings,
    crawlErrors: [],
  };

  if (format === 'html') {
    // Prefer the pipeline pre-rendered cache; fall back to on-demand build.
    const html = scan.htmlReportCache ?? buildReportHtml(input);
    return new NextResponse(html, {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'x-content-type-options': 'nosniff',
        ...(download ? { 'content-disposition': `attachment; filename="scan-report-${scan.id}.html"` } : {}),
      },
    });
  }

  if (format === 'json') {
    const report = buildReportJson(input);
    return new NextResponse(JSON.stringify(report, null, 2), {
      status: 200,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        ...(download ? { 'content-disposition': `attachment; filename="scan-report-${scan.id}.json"` } : {}),
      },
    });
  }

  return NextResponse.json({ error: 'Unsupported format. Use json or html.' }, { status: 400 });
}
