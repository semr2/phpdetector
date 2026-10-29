import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** GET /api/health — Health and readiness check (SRS §8). */
export async function GET() {
  try {
    await db.scan.count();
    return NextResponse.json({ status: 'ok', database: 'reachable' });
  } catch {
    return NextResponse.json({ status: 'ok', database: 'unreachable' }, { status: 200 });
  }
}
