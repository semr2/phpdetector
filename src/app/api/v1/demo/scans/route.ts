import { NextResponse } from 'next/server';
import { isDemoModeEnabled } from '@/lib/core/demo-mode';
import { getDemoScanList, DEMO_REPORT_NOTICE } from '@/lib/services/demo-fixture-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET() {
  if (!isDemoModeEnabled()) {
    return NextResponse.json({ error: 'Demo fixtures are disabled.' }, { status: 404 });
  }
  return NextResponse.json(
    { simulated: true, notice: DEMO_REPORT_NOTICE, scans: getDemoScanList() },
    { headers: { 'cache-control': 'no-store' } },
  );
}
