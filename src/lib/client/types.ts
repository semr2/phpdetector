/**
 * Client-side contracts mirroring the REST API (SRS §8).
 */

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';
export type PhpDetection = 'likely' | 'not_detected' | 'inconclusive';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'confirmed' | 'potential' | 'inconclusive';
export type FeatureKind =
  | 'form_login'
  | 'form_search'
  | 'form_upload'
  | 'form_generic'
  | 'query_param'
  | 'php_route'
  | 'file_route';

export interface Evidence {
  source: string;
  observation: string;
  timestamp: string;
}

export interface ScanCounts {
  findings: number;
  features: number;
  pages: number;
}

export interface ScanListItem {
  id: string;
  targetUrl: string;
  mode: 'live' | 'demo';
  status: ScanStatus;
  progress: number;
  currentStep: number;
  phpDetection: PhpDetection | null;
  error: string | null;
  createdAt: string;
  completedAt: string | null;
  counts: ScanCounts;
}

export interface ScanSummary {
  pagesCrawled: number;
  featuresTotal: number;
  findingsTotal: number;
  findingsBySeverity: Record<Severity, number>;
  findingsByStatus: Record<FindingStatus, number>;
  durationMs?: number;
}

export interface ScanDetail extends ScanListItem {
  phpFramework: string | null;
  phpEvidence: Evidence[] | null;
  summary: ScanSummary | null;
  startedAt: string | null;
}

export interface FindingItem {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  status: FindingStatus;
  affectedUrl: string;
  evidence: Evidence[];
  remediation: string;
}

export interface FindingPage {
  total: number;
  page: number;
  pageSize: number;
  findings: FindingItem[];
}

export interface FeatureItem {
  id: string;
  kind: FeatureKind;
  name: string;
  location: string;
  details: string | null;
}

export const PIPELINE_STEP_LABELS = [
  'API Request Validation',
  'Network Scope Check',
  'Scan Record Init',
  'Base Fetching',
  'Fingerprint Analysis',
  'Bounded Crawl',
  'Feature Extraction',
  'Rule Execution',
  'Finding Normalization',
  'Persistence',
  'Report Generation',
  'State Finalization',
] as const;

export const FEATURE_KIND_LABELS: Record<FeatureKind, string> = {
  form_login: 'Login form',
  form_search: 'Search form',
  form_upload: 'Upload form',
  form_generic: 'Generic form',
  query_param: 'Query parameter',
  php_route: 'PHP route',
  file_route: 'File-handling route',
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const severityRank = (s: Severity): number => SEVERITY_RANK[s] ?? 9;

/** Fetch wrapper with structured error handling. */
export async function apiFetch<T>(input: string, init?: RequestInit): Promise<T> {
  const response = await fetch(input, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  });
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new Error(data.error ?? `Request failed (${response.status})`);
  }
  return data;
}
