import { z } from 'zod';
import phpDetectedFixture from '../../../fixtures/demo/php-detected.json';
import phpNotDetectedFixture from '../../../fixtures/demo/php-not-detected.json';
import phpInconclusiveFixture from '../../../fixtures/demo/php-inconclusive.json';
import featuresFixture from '../../../fixtures/demo/example-features.json';
import findingsFixture from '../../../fixtures/demo/example-findings.json';
import reportFixture from '../../../fixtures/demo/example-scan-report.json';
import { DEMO_SIMULATION_NOTICE, isDemoModeEnabled } from '@/lib/core/demo-mode';
import type { FeatureItem, FindingItem, ScanDetail, ScanListItem } from '@/lib/client/types';
import type { FeatureRecord, FindingRecord, PhpDetectionResult, ScanSummary } from '@/lib/domain/types';
import { FEATURE_KIND_LABELS } from '@/lib/domain/types';
import { buildReportJson, type ReportInput } from './report';

const PhpEvidenceSchema = z.object({
  indicator: z.string(),
  value: z.string(),
  strength: z.enum(['strong', 'medium', 'weak']),
  source: z.enum(['header', 'cookie', 'url', 'body']),
  explanation: z.string(),
}).strict();

const PhpDetectionResultSchema = z.object({
  status: z.enum(['likely', 'not_detected', 'inconclusive']),
  evidence: z.array(PhpEvidenceSchema),
  frameworks: z.array(z.string()),
  phpVersion: z.string().optional(),
  assessment: z.object({
    method: z.literal('heuristic'),
    calibrated: z.literal(false),
    explanation: z.string(),
  }).strict(),
}).strict();

const ScanSummarySchema = z.object({
  pagesCrawled: z.number().int().nonnegative(),
  featuresTotal: z.number().int().nonnegative(),
  findingsTotal: z.number().int().nonnegative(),
  findingsBySeverity: z.object({
    critical: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    low: z.number().int().nonnegative(),
    info: z.number().int().nonnegative(),
  }).strict(),
  findingsByStatus: z.object({
    confirmed: z.literal(0),
    potential: z.number().int().nonnegative(),
    inconclusive: z.number().int().nonnegative(),
  }).strict(),
  durationMs: z.number().nonnegative().optional(),
}).strict();

const ScanDetailSchema = z.object({
  id: z.string().min(1),
  targetUrl: z.string().url(),
  mode: z.literal('demo'),
  status: z.literal('completed'),
  progress: z.literal(100),
  currentStep: z.number().int().positive(),
  phpDetection: z.enum(['likely', 'not_detected', 'inconclusive']),
  phpFramework: z.string().nullable(),
  phpEvidence: PhpDetectionResultSchema,
  summary: ScanSummarySchema,
  error: z.null(),
  startedAt: z.string().datetime(),
  completedAt: z.string().datetime(),
  createdAt: z.string().datetime(),
  counts: z.object({ findings: z.number().int().nonnegative(), features: z.number().int().nonnegative(), pages: z.number().int().nonnegative() }).strict(),
}).strict();

const PageFixtureSchema = z.object({ url: z.string().url(), httpStatus: z.number().int(), depth: z.number().int().nonnegative() }).strict();
const DemoScanFixtureSchema = ScanDetailSchema.extend({ pages: z.array(PageFixtureSchema) }).strict();

const FeatureItemSchema = z.object({
  id: z.string().min(1),
  kind: z.enum(['form_login', 'form_search', 'form_upload', 'form_generic', 'query_param', 'php_route', 'file_route']),
  name: z.string(),
  location: z.string().url(),
  details: z.string().nullable(),
}).strict();

const FindingItemSchema = z.object({
  id: z.string().min(1),
  ruleId: z.string(),
  title: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  confidence: z.enum(['high', 'medium', 'low']),
  status: z.enum(['potential', 'inconclusive']),
  affectedUrl: z.string().url(),
  evidence: z.array(z.object({ source: z.string(), observation: z.string(), timestamp: z.string().datetime() }).strict()),
  remediation: z.string(),
}).strict();

const ReportFindingSchema = z.object({
  rule_id: z.string(), title: z.string(), severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  confidence: z.enum(['high', 'medium', 'low']), status: z.enum(['potential', 'inconclusive']),
  affected_url: z.string().url(), evidence: z.array(z.object({ source: z.string(), observation: z.string(), timestamp: z.string().datetime() }).strict()),
  remediation: z.string(),
}).strict();

// Reports serialize an unknown PHP version as null; scan results omit it.
const ReportPhpDetectionResultSchema = PhpDetectionResultSchema.extend({
  phpVersion: z.string().nullable().optional(),
});

const ReportFixtureSchema = z.object({
  report: z.object({
    generator: z.string(), generatedAt: z.string().datetime(),
    scan: z.object({
      id: z.string(), targetUrl: z.string().url(), mode: z.literal('demo'), status: z.literal('completed'),
      createdAt: z.string().datetime(), completedAt: z.string().datetime().nullable(),
    }).strict(),
    phpDetection: ReportPhpDetectionResultSchema,
    summary: ScanSummarySchema,
    pages: z.array(PageFixtureSchema),
    features: z.array(z.object({ kind: z.string(), label: z.string(), name: z.string(), location: z.string().url(), details: z.record(z.string(), z.unknown()).nullable() }).strict()),
    findings: z.array(ReportFindingSchema),
    crawlErrors: z.array(z.object({ url: z.string(), reason: z.string() }).strict()),
    simulated: z.literal(true),
    simulationNotice: z.string().min(1),
  }).strict(),
}).strict();

// Parse and validate every imported JSON fixture at module load. Fixture failures
// fail closed instead of returning malformed or misleading demo data.
const scanFixtures = [phpDetectedFixture, phpNotDetectedFixture, phpInconclusiveFixture]
  .map((fixture) => DemoScanFixtureSchema.parse(fixture));
const featuresByScan = z.record(z.string(), z.array(FeatureItemSchema)).parse(featuresFixture);
const findingsByScan = z.record(z.string(), z.array(FindingItemSchema)).parse(findingsFixture);
const exampleReport = ReportFixtureSchema.parse(reportFixture);

if (exampleReport.report.simulationNotice !== DEMO_SIMULATION_NOTICE) {
  throw new Error('Demo report fixture must use the current simulated-data notice.');
}

const scanById = new Map(scanFixtures.map((scan) => [scan.id, scan]));

function assertDemoModeEnabled(): void {
  if (!isDemoModeEnabled()) throw new Error('Demo fixtures are disabled.');
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

export function getDemoScanList(): ScanListItem[] {
  assertDemoModeEnabled();
  return scanFixtures.map(({ pages: _pages, phpEvidence: _phpEvidence, phpFramework: _phpFramework, summary: _summary, startedAt: _startedAt, ...scan }) => clone(scan));
}

export function getDemoScanDetail(id: string): (ScanDetail & { pages: Array<z.infer<typeof PageFixtureSchema>> }) | null {
  assertDemoModeEnabled();
  const scan = scanById.get(id);
  return scan ? clone(scan) : null;
}

export function getDemoFeatures(id: string): FeatureItem[] | null {
  assertDemoModeEnabled();
  if (!scanById.has(id)) return null;
  return clone(featuresByScan[id] ?? []);
}

export function getDemoFindings(id: string): FindingItem[] | null {
  assertDemoModeEnabled();
  if (!scanById.has(id)) return null;
  return clone(findingsByScan[id] ?? []);
}

function toReportInput(id: string): ReportInput | null {
  const scan = scanById.get(id);
  if (!scan) return null;
  const features = featuresByScan[id] ?? [];
  const findings = findingsByScan[id] ?? [];
  const featureRecords: FeatureRecord[] = features.map((feature) => {
    let details: Record<string, unknown> | undefined;
    if (feature.details) {
      try { details = JSON.parse(feature.details) as Record<string, unknown>; } catch { details = undefined; }
    }
    return { kind: feature.kind, name: feature.name, location: feature.location, details };
  });
  const findingRecords: FindingRecord[] = findings.map(({ id: _id, ...finding }) => finding);
  return {
    id: scan.id,
    targetUrl: scan.targetUrl,
    mode: 'demo',
    status: scan.status,
    createdAt: scan.createdAt,
    completedAt: scan.completedAt,
    php: scan.phpEvidence as PhpDetectionResult,
    summary: scan.summary as ScanSummary,
    pages: clone(scan.pages),
    features: featureRecords,
    findings: findingRecords,
    generatedAt: exampleReport.report.generatedAt,
    simulationNotice: DEMO_SIMULATION_NOTICE,
  };
}

export function getDemoReport(id: string): Record<string, unknown> | null {
  assertDemoModeEnabled();
  const input = toReportInput(id);
  if (!input) return null;
  const report = buildReportJson(input);
  return ReportFixtureSchema.parse(report);
}

export function getDemoExampleReportFixture(): Record<string, unknown> {
  assertDemoModeEnabled();
  return clone(exampleReport);
}

export function getDemoReportInput(id: string): ReportInput | null {
  assertDemoModeEnabled();
  return toReportInput(id);
}

export function getDemoFindingRecords(id: string): FindingRecord[] | null {
  const findings = getDemoFindings(id);
  return findings?.map(({ id: _id, ...finding }) => finding as FindingRecord) ?? null;
}

export const DEMO_SCAN_IDS = scanFixtures.map((scan) => scan.id);
export const DEMO_REPORT_NOTICE = DEMO_SIMULATION_NOTICE;
