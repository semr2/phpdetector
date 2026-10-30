import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { GET as listDemoScans } from '../src/app/api/v1/demo/scans/route.ts';
import { GET as getDemoScan } from '../src/app/api/v1/demo/scans/[id]/route.ts';
import { GET as getDemoFeatures } from '../src/app/api/v1/demo/scans/[id]/features/route.ts';
import { GET as getDemoFindings } from '../src/app/api/v1/demo/scans/[id]/findings/route.ts';
import { GET as getDemoReport } from '../src/app/api/v1/demo/scans/[id]/report/route.ts';
import { POST as createLiveScan } from '../src/app/api/v1/scans/route.ts';

async function withEnvironment<T>(demoMode: string | undefined, nodeEnv: string, fn: () => Promise<T>): Promise<T> {
  const env = process.env as Record<string, string | undefined>;
  const previousDemoMode = process.env.DEMO_MODE;
  const previousNodeEnv = process.env.NODE_ENV;
  if (demoMode === undefined) delete process.env.DEMO_MODE;
  else process.env.DEMO_MODE = demoMode;
  env.NODE_ENV = nodeEnv;
  try {
    return await fn();
  } finally {
    if (previousDemoMode === undefined) delete process.env.DEMO_MODE;
    else process.env.DEMO_MODE = previousDemoMode;
    if (previousNodeEnv === undefined) delete env.NODE_ENV;
    else env.NODE_ENV = previousNodeEnv;
  }
}

test('demo APIs serve labelled fixtures, filters, and reports without creating live scans', async () => {
  await withEnvironment('true', 'test', async () => {
    const listResponse = await listDemoScans();
    assert.equal(listResponse.status, 200);
    const listBody = await listResponse.json() as { simulated: boolean; notice: string; scans: Array<{ id: string }> };
    assert.equal(listBody.simulated, true);
    assert.match(listBody.notice, /^SIMULATED DEMO DATA/);
    assert.equal(listBody.scans.length, 3);

    const params = Promise.resolve({ id: 'demo-php-detected' });
    const detailResponse = await getDemoScan(new NextRequest('http://localhost'), { params });
    assert.equal(detailResponse.status, 200);
    const detail = await detailResponse.json() as { simulated: boolean; targetUrl: string; mode: string };
    assert.equal(detail.simulated, true);
    assert.equal(detail.mode, 'demo');
    assert.match(detail.targetUrl, /example\.invalid/);

    const featuresResponse = await getDemoFeatures(new NextRequest('http://localhost'), { params });
    assert.equal(featuresResponse.status, 200);
    const featureBody = await featuresResponse.json() as { simulated: boolean; features: unknown[] };
    assert.equal(featureBody.simulated, true);
    assert.ok(featureBody.features.length > 0);

    const findingsRequest = new NextRequest('http://localhost/api/v1/demo/scans/demo-php-detected/findings?status=potential');
    const findingsResponse = await getDemoFindings(findingsRequest, { params });
    assert.equal(findingsResponse.status, 200);
    const findingsBody = await findingsResponse.json() as { simulated: boolean; total: number; findings: Array<{ status: string }> };
    assert.equal(findingsBody.simulated, true);
    assert.ok(findingsBody.findings.every((finding) => finding.status === 'potential'));

    const confirmedRequest = new NextRequest('http://localhost/api/v1/demo/scans/demo-php-detected/findings?status=confirmed');
    const confirmedResponse = await getDemoFindings(confirmedRequest, { params });
    const confirmedBody = await confirmedResponse.json() as { total: number; findings: unknown[] };
    assert.equal(confirmedBody.total, 0);
    assert.deepEqual(confirmedBody.findings, []);

    const jsonReportResponse = await getDemoReport(new NextRequest('http://localhost/api/v1/demo/scans/demo-php-detected/report?format=json'), { params });
    assert.equal(jsonReportResponse.status, 200);
    assert.equal(jsonReportResponse.headers.get('x-demo-data'), 'simulated');
    const jsonReport = await jsonReportResponse.json() as { report: { simulated: boolean; findings: Array<{ status: string }> } };
    assert.equal(jsonReport.report.simulated, true);
    assert.ok(jsonReport.report.findings.every((finding) => finding.status !== 'confirmed'));

    const htmlResponse = await getDemoReport(new NextRequest('http://localhost/api/v1/demo/scans/demo-php-detected/report?format=html'), { params });
    assert.match(await htmlResponse.text(), /SIMULATED DEMO DATA/);

    const csvResponse = await getDemoReport(new NextRequest('http://localhost/api/v1/demo/scans/demo-php-detected/report?format=csv'), { params });
    const csv = await csvResponse.text();
    assert.match(csv, /^data_origin,/);
    assert.match(csv, /SIMULATED DEMO DATA/);

    const livePost = await createLiveScan(new NextRequest('http://localhost/api/v1/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: 'http://127.0.0.1', demo: true }),
    }));
    assert.equal(livePost.status, 400);
    assert.match((await livePost.json() as { error: string }).error, /separate from live scans/i);
  });
});

test('demo APIs are unavailable when disabled and in production', async () => {
  await withEnvironment(undefined, 'development', async () => {
    assert.equal((await listDemoScans()).status, 404);
  });
  await withEnvironment('true', 'production', async () => {
    assert.equal((await listDemoScans()).status, 404);
    assert.equal((await getDemoScan(new NextRequest('http://localhost'), { params: Promise.resolve({ id: 'demo-php-detected' }) })).status, 404);
  });
});
