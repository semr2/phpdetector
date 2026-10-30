import { NextResponse } from 'next/server';
import { isDemoModeEnabled } from '@/lib/core/demo-mode';
import { getDemoFeatures } from '@/lib/services/demo-fixture-service';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  if (!isDemoModeEnabled()) {
    return NextResponse.json({ error: 'Demo fixtures are disabled.' }, { status: 404 });
  }
  const { id } = await params;
  const features = getDemoFeatures(id);
  if (!features) return NextResponse.json({ error: 'Demo scan not found' }, { status: 404 });
  return NextResponse.json({ simulated: true, features }, { headers: { 'cache-control': 'no-store' } });
}
