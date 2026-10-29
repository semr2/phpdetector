import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import type { FeatureItem } from '@/lib/client/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** GET /api/v1/scans/{id}/features — full feature inventory for a scan. */
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;

  const scan = await db.scan.findUnique({ where: { id }, select: { id: true } });
  if (!scan) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const rows = await db.feature.findMany({
    where: { scanId: id },
    orderBy: [{ kind: 'asc' }, { name: 'asc' }],
  });

  const features: FeatureItem[] = rows.map((f) => ({
    id: f.id,
    kind: f.kind as FeatureItem['kind'],
    name: f.name,
    location: f.location,
    details: f.details,
  }));

  return NextResponse.json({ features });
}
