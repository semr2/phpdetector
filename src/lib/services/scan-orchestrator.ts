import { db } from '@/lib/db';
import { TOTAL_STEPS, PIPELINE_STEPS, SCANNER_CONFIG } from '@/lib/core/config';
import { safeFetch } from '@/lib/core/http-client';
import { assertHostInScope, ScopeViolationError } from '@/lib/core/network-scope';
import { validateTargetUrl, UrlValidationError } from '@/lib/core/url-validation';
import { createLogger } from '@/lib/core/logger';
import type {
  FindingRecord,
  FeatureRecord,
  RawObservation,
  ScanSummary,
  Severity,
  FindingStatus,
} from '@/lib/domain/types';
import { SEVERITY_ORDER } from '@/lib/domain/types';
import { crawl } from '@/lib/scanner/crawler';
import { parseHtml } from '@/lib/scanner/html';
import { extractFeatures } from '@/lib/scanner/feature-extractor';
import { detectPhp, type RootObservables } from '@/lib/scanner/php-detector';
import { runRules } from '@/lib/scanner/rules';
import { buildReportHtml } from './report';

/**
 * The 12-step evidence-driven scan pipeline (SRS §5), executed deterministically:
 *   1  API Request Validation      7  Feature Extraction
 *   2  Network Scope Check         8  Rule Execution
 *   3  Scan Record Initialization  9  Finding Normalization
 *   4  Base Fetching              10  Persistence
 *   5  Fingerprint Analysis       11  Report Generation
 *   6  Bounded Crawl              12  State Finalization
 *
 * Demo fixtures are served by a separate read-only service and never enter
 * this live network scanner or its persistence path.
 */

const log = createLogger('orchestrator');

const SEVERITIES: Severity[] = SEVERITY_ORDER;

/** Best-effort page title for the Page table; never throws. */
function pageTitle(o: RawObservation): string | null {
  try {
    const title = parseHtml(o.body, o.url).title;
    return title && title !== o.url ? title.slice(0, 300) : null;
  } catch {
    return null;
  }
}
const STATUSES: FindingStatus[] = ['confirmed', 'potential', 'inconclusive'];

async function setStep(scanId: string, step: number, extra?: { phpDetection?: string; phpEvidence?: string; phpFramework?: string }): Promise<void> {
  const progress = Math.min(100, Math.round((step / TOTAL_STEPS) * 100));
  await db.scan.update({
    where: { id: scanId },
    data: { currentStep: step, progress, status: 'running', ...extra },
  });
}

export async function executeScan(scanId: string, targetUrl: string): Promise<void> {
  const startedAt = Date.now();
  try {
    await db.scan.update({
      where: { id: scanId },
      data: { status: 'running', startedAt: new Date() },
    });

    // ---------------------------------------------------------------- Step 1
    await setStep(scanId, 1);
    const target = validateTargetUrl(targetUrl);
    log.info('pipeline: request validated', { scanId, url: target.url, mode: 'live' });

    // ---------------------------------------------------------------- Step 2
    await setStep(scanId, 2);
    const scope = await assertHostInScope(target.host);
    const scopeAddresses = scope.addresses;
    log.info('pipeline: scope check passed', { scanId, addresses: scopeAddresses });

    // ---------------------------------------------------------------- Step 3
    await setStep(scanId, 3); // record already persisted; step marks init complete

    // ---------------------------------------------------------------- Step 4
    await setStep(scanId, 4);
    let root: RawObservation;
    let baseError: string | null = null;
    try {
      const result = await safeFetch(target.url);
      root = {
        url: result.finalUrl,
        status: result.status,
        headers: result.headers,
        setCookies: result.setCookies,
        body: result.body,
        depth: 0,
      };
    } catch (error) {
      baseError = error instanceof Error ? error.message : 'Base fetch failed';
      log.warn('pipeline: base fetch failed', { scanId, error: baseError });
      // Base fetch failure is fatal for evidence gathering — go to failure.
      await db.scan.update({
        where: { id: scanId },
        data: {
          status: 'failed',
          error: `Base fetch failed: ${baseError}`,
          completedAt: new Date(),
          progress: 100,
        },
      });
      return;
    }

    // ---------------------------------------------------------------- Step 5
    await setStep(scanId, 5);
    const rootObservables: RootObservables = {
      headers: root.headers,
      setCookies: root.setCookies,
      urls: [root.url],
      body: root.body,
    };
    const php = detectPhp(rootObservables);
    log.info('pipeline: fingerprint complete', {
      scanId,
      detection: php.status,
      frameworks: php.frameworks,
      evidence: php.evidence.length,
    });

    // ---------------------------------------------------------------- Step 6
    await setStep(scanId, 6);
    let observations: RawObservation[];
    let crawlErrors: Array<{ url: string; reason: string }> = [];
    const crawlResult = await crawl(target.url);
    observations = crawlResult.observations.length > 0 ? crawlResult.observations : [root];
    crawlErrors = crawlResult.errors;

    // ---------------------------------------------------------------- Step 7
    await setStep(scanId, 7);
    const features: FeatureRecord[] = extractFeatures(observations);

    // ---------------------------------------------------------------- Step 8
    await setStep(scanId, 8);
    const findings: FindingRecord[] = runRules({
      baseUrl: target.url,
      root,
      observations,
      php,
    });

    // ---------------------------------------------------------------- Step 9
    await setStep(scanId, 9);
    // Normalization: ensure every finding carries valid enums + sorted evidence.
    const normalized = findings.map((f) => ({
      ...f,
      severity: SEVERITIES.includes(f.severity) ? f.severity : 'info',
      status: STATUSES.includes(f.status) ? f.status : 'inconclusive',
      evidence: f.evidence.slice(0, 5),
    }));

    // ---------------------------------------------------------------- Step 10
    await setStep(scanId, 10);
    await db.page.deleteMany({ where: { scanId } });
    if (observations.length > 0) {
      await db.page.createMany({
        data: observations.map((o) => ({
          scanId,
          url: o.url.slice(0, 2000),
          httpStatus: o.status,
          depth: o.depth,
          title: pageTitle(o),
        })),
      });
    }
    await db.feature.deleteMany({ where: { scanId } });
    if (features.length > 0) {
      await db.feature.createMany({
        data: features.map((f) => ({
          scanId,
          kind: f.kind,
          name: f.name.slice(0, 300),
          location: f.location.slice(0, 2000),
          details: f.details ? JSON.stringify(f.details) : null,
        })),
      });
    }
    await db.finding.deleteMany({ where: { scanId } });
    if (normalized.length > 0) {
      await db.finding.createMany({
        data: normalized.map((f) => ({
          scanId,
          ruleId: f.ruleId,
          title: f.title,
          severity: f.severity,
          confidence: f.confidence,
          status: f.status,
          affectedUrl: f.affectedUrl.slice(0, 2000),
          evidence: JSON.stringify(f.evidence),
          remediation: f.remediation,
        })),
      });
    }

    // ---------------------------------------------------------------- Step 11
    await setStep(scanId, 11);
    const summary: ScanSummary = {
      pagesCrawled: observations.length,
      featuresTotal: features.length,
      findingsTotal: normalized.length,
      findingsBySeverity: Object.fromEntries(
        SEVERITIES.map((s) => [s, normalized.filter((f) => f.severity === s).length]),
      ) as Record<Severity, number>,
      findingsByStatus: Object.fromEntries(
        STATUSES.map((s) => [s, normalized.filter((f) => f.status === s).length]),
      ) as Record<FindingStatus, number>,
      durationMs: Date.now() - startedAt,
    };

    // Pre-render the standalone HTML report and store it on the scan record so
    // /report?format=html can stream instantly without re-running the pipeline.
    let htmlReport: string | null = null;
    try {
      htmlReport = buildReportHtml({
        id: scanId,
        targetUrl: target.url,
        mode: 'live',
        status: 'completed',
        createdAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        php,
        summary,
        pages: observations.map((o) => ({ url: o.url, httpStatus: o.status, depth: o.depth })),
        features,
        findings: normalized,
        crawlErrors,
      });
    } catch (error) {
      log.warn('pipeline: HTML report pre-render failed', {
        scanId,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    // ---------------------------------------------------------------- Step 12
    await db.scan.update({
      where: { id: scanId },
      data: {
        status: 'completed',
        progress: 100,
        currentStep: TOTAL_STEPS,
        phpDetection: php.status,
        // Store the complete structured detector result in this JSON column.
        phpEvidence: JSON.stringify(php),
        phpFramework: php.frameworks.join(', ') || null,
        summary: JSON.stringify(summary),
        htmlReportCache: htmlReport,
        crawlErrorCount: crawlErrors.length,
        completedAt: new Date(),
      },
    });

    log.info('scan completed', {
      scanId,
      mode: 'live',
      pages: summary.pagesCrawled,
      features: summary.featuresTotal,
      findings: summary.findingsTotal,
      durationMs: summary.durationMs,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown pipeline error';
    log.error('scan failed', { scanId, error: message });
    try {
      await db.scan.update({
        where: { id: scanId },
        data: {
          status: 'failed',
          error: message.slice(0, 1000),
          completedAt: new Date(),
          progress: 100,
        },
      });
    } catch (dbError) {
      log.error('failed to persist scan failure', {
        scanId,
        error: dbError instanceof Error ? dbError.message : String(dbError),
      });
    }
  }
}

const STALE_SCAN_AFTER_MS = 10 * 60 * 1000;
const RECOVERY_MIN_INTERVAL_MS = 60 * 1000;
let lastRecoveryAt = 0;

/**
 * Scans run in-process, so a restart leaves rows stuck as queued/running.
 * Any unfinished scan untouched for STALE_SCAN_AFTER_MS is marked failed so
 * the UI never polls a dead scan forever. Throttled; safe to call often.
 */
export async function recoverStaleScans(now: number = Date.now()): Promise<number> {
  if (now - lastRecoveryAt < RECOVERY_MIN_INTERVAL_MS) return 0;
  lastRecoveryAt = now;
  try {
    const result = await db.scan.updateMany({
      where: {
        status: { in: ['queued', 'running'] },
        updatedAt: { lt: new Date(now - STALE_SCAN_AFTER_MS) },
      },
      data: {
        status: 'failed',
        error: 'Scan interrupted (server restart or timeout) before completion',
        completedAt: new Date(now),
        progress: 100,
      },
    });
    if (result.count > 0) log.warn('recovered stale scans', { count: result.count });
    return result.count;
  } catch (error) {
    log.warn('stale scan recovery failed', {
      error: error instanceof Error ? error.message : String(error),
    });
    return 0;
  }
}

/** Fire-and-forget launcher used by the API route (background execution). */
export function launchScan(scanId: string, targetUrl: string): void {
  void executeScan(scanId, targetUrl);
}

// Re-exported for API input validation.
export { validateTargetUrl, UrlValidationError, ScopeViolationError, SCANNER_CONFIG };
