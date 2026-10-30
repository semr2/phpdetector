import { NextRequest, NextResponse } from 'next/server';
import { isDemoModeEnabled } from '@/lib/core/demo-mode';
import { DEMO_REPORT_NOTICE, getDemoFindingRecords, getDemoReport, getDemoReportInput } from '@/lib/services/demo-fixture-service';
import { buildFindingsCsv, buildReportHtml } from '@/lib/services/report';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  if (!isDemoModeEnabled()) {
    return NextResponse.json({ error: 'Demo fixtures are disabled.' }, { status: 404 });
  }
  const { id } = await params;
  const input = getDemoReportInput(id);
  if (!input) return NextResponse.json({ error: 'Demo scan not found' }, { status: 404 });

  const url = new URL(request.url);
  const format = (url.searchParams.get('format') ?? 'json').toLowerCase();
  const download = url.searchParams.get('download') === '1';
  const filenamePrefix = 'simulated-demo';
  const commonHeaders = { 'x-demo-data': 'simulated', 'cache-control': 'no-store' };

  if (format === 'html') {
    return new NextResponse(buildReportHtml(input), {
      headers: {
        ...commonHeaders,
        'content-type': 'text/html; charset=utf-8',
        'x-content-type-options': 'nosniff',
        ...(download ? { 'content-disposition': `attachment; filename="${filenamePrefix}-report-${id}.html"` } : {}),
      },
    });
  }
  if (format === 'csv') {
    const findings = getDemoFindingRecords(id);
    if (!findings) return NextResponse.json({ error: 'Demo scan not found' }, { status: 404 });
    return new NextResponse(buildFindingsCsv(findings, { simulated: true, simulationNotice: DEMO_REPORT_NOTICE }), {
      headers: {
        ...commonHeaders,
        'content-type': 'text/csv; charset=utf-8',
        'x-content-type-options': 'nosniff',
        'content-disposition': `attachment; filename="${filenamePrefix}-findings-${id}.csv"`,
      },
    });
  }
  if (format === 'json') {
    const report = getDemoReport(id);
    if (!report) return NextResponse.json({ error: 'Demo scan not found' }, { status: 404 });
    return new NextResponse(JSON.stringify(report, null, 2), {
      headers: {
        ...commonHeaders,
        'content-type': 'application/json; charset=utf-8',
        ...(download ? { 'content-disposition': `attachment; filename="${filenamePrefix}-report-${id}.json"` } : {}),
      },
    });
  }
  return NextResponse.json({ error: 'Unsupported format. Use json, html or csv.' }, { status: 400 });
}
