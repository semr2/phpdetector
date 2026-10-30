import { NextRequest, NextResponse } from 'next/server';
import { isDemoModeEnabled } from '@/lib/core/demo-mode';
import { getDemoFindings } from '@/lib/services/demo-fixture-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const STATUSES = ['potential', 'inconclusive'] as const;

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  if (!isDemoModeEnabled()) {
    return NextResponse.json({ error: 'Demo fixtures are disabled.' }, { status: 404 });
  }
  const { id } = await params;
  const allFindings = getDemoFindings(id);
  if (!allFindings) return NextResponse.json({ error: 'Demo scan not found' }, { status: 404 });

  const url = new URL(request.url);
  const severity = url.searchParams.get('severity');
  const status = url.searchParams.get('status');
  const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);
  const pageSize = Math.min(100, Math.max(1, Number(url.searchParams.get('pageSize') ?? '20') || 20));
  const validStatus = !status || (STATUSES as readonly string[]).includes(status);
  const filtered = validStatus
    ? allFindings.filter((finding) =>
        (!severity || !(SEVERITIES as readonly string[]).includes(severity) || finding.severity === severity) &&
        (!status || finding.status === status),
      )
    : [];
  const start = (page - 1) * pageSize;
  return NextResponse.json({
    simulated: true,
    total: filtered.length,
    page,
    pageSize,
    findings: filtered.slice(start, start + pageSize),
  }, { headers: { 'cache-control': 'no-store' } });
}
