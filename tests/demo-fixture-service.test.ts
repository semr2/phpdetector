import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isDemoModeEnabled } from '../src/lib/core/demo-mode.ts';
import {
  DEMO_SCAN_IDS,
  getDemoExampleReportFixture,
  getDemoFeatures,
  getDemoFindings,
  getDemoReport,
  getDemoScanDetail,
  getDemoScanList,
} from '../src/lib/services/demo-fixture-service.ts';

async function withDemoEnvironment<T>(fn: () => Promise<T> | T): Promise<T> {
  const env = process.env as Record<string, string | undefined>;
  const previousDemoMode = process.env.DEMO_MODE;
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.DEMO_MODE = 'true';
  env.NODE_ENV = 'test';
  try {
    return await fn();
  } finally {
    if (previousDemoMode === undefined) delete process.env.DEMO_MODE;
    else process.env.DEMO_MODE = previousDemoMode;
    if (previousNodeEnv === undefined) delete env.NODE_ENV;
    else env.NODE_ENV = previousNodeEnv;
  }
}

test('demo flag is explicit and always off in production', () => {
  assert.equal(isDemoModeEnabled(undefined, 'development'), false);
  assert.equal(isDemoModeEnabled('false', 'development'), false);
  assert.equal(isDemoModeEnabled('true', 'development'), true);
  assert.equal(isDemoModeEnabled('true', 'production'), false);
});

test('validated static fixtures cover all PHP detection outcomes and are isolated copies', async () => {
  await withDemoEnvironment(() => {
    const scans = getDemoScanList();
    assert.deepEqual(scans.map((scan) => scan.id), DEMO_SCAN_IDS);
    assert.deepEqual(scans.map((scan) => scan.phpDetection), ['likely', 'not_detected', 'inconclusive']);
    assert.ok(scans.every((scan) => scan.mode === 'demo' && scan.status === 'completed'));
    scans[0].targetUrl = 'https://changed.example.invalid/';
    assert.notEqual(getDemoScanList()[0].targetUrl, scans[0].targetUrl);
  });
});

test('fixture findings are never confirmed and feature examples match application types', async () => {
  await withDemoEnvironment(() => {
    for (const id of DEMO_SCAN_IDS) {
      const detail = getDemoScanDetail(id);
      const features = getDemoFeatures(id);
      const findings = getDemoFindings(id);
      assert.ok(detail);
      assert.ok(features);
      assert.ok(findings);
      assert.equal(detail.counts.pages, detail.pages.length);
      assert.equal(detail.counts.features, features.length);
      assert.equal(detail.counts.findings, findings.length);
      assert.ok(findings.every((finding) => finding.status === 'potential' || finding.status === 'inconclusive'));
    }
    assert.ok((getDemoFeatures('demo-php-detected') ?? []).some((feature) => feature.kind === 'form_upload'));
    assert.ok((getDemoFeatures('demo-php-detected') ?? []).some((feature) => feature.kind === 'php_route'));
  });
});

test('example scan report is schema-valid and fixture report output is deterministic', async () => {
  await withDemoEnvironment(() => {
    const example = getDemoExampleReportFixture();
    const first = getDemoReport('demo-php-detected');
    const second = getDemoReport('demo-php-detected');
    assert.deepEqual(first, example);
    assert.deepEqual(second, first);
    const report = (first as { report: { simulated: boolean; simulationNotice: string; findings: Array<{ status: string }> } }).report;
    assert.equal(report.simulated, true);
    assert.match(report.simulationNotice, /^SIMULATED DEMO DATA/);
    assert.ok(report.findings.every((finding) => finding.status !== 'confirmed'));

    for (const id of DEMO_SCAN_IDS) {
      const fixtureReport = getDemoReport(id) as { report: { phpDetection: { status: string } } };
      const scanDetail = getDemoScanDetail(id);
      assert.ok(scanDetail);
      assert.ok(scanDetail.phpEvidence);
      assert.equal(fixtureReport.report.phpDetection.status, scanDetail.phpEvidence.status);
    }
  });
});

test('fixture service is inaccessible when disabled or in production', () => {
  const env = process.env as Record<string, string | undefined>;
  const previousDemoMode = process.env.DEMO_MODE;
  const previousNodeEnv = process.env.NODE_ENV;
  try {
    process.env.DEMO_MODE = 'true';
    env.NODE_ENV = 'production';
    assert.throws(() => getDemoScanList(), /disabled/i);
  } finally {
    if (previousDemoMode === undefined) delete process.env.DEMO_MODE;
    else process.env.DEMO_MODE = previousDemoMode;
    if (previousNodeEnv === undefined) delete env.NODE_ENV;
    else env.NODE_ENV = previousNodeEnv;
  }
});
