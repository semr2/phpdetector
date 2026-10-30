/**
 * Domain contracts for the PHP Feature & Vulnerability Detection System.
 *
 * Core architectural principle (SRS §1): the system distinguishes
 *   (1) Is PHP likely used?            -> PhpDetectionResult
 *   (2) Which application features exist? -> FeatureRecord
 *   (3) Does evidence demonstrate a weakness? -> Finding
 * A site is never flagged vulnerable merely because it uses PHP or exposes a feature.
 *
 * Severity (potential impact) and Confidence (evidence strength) are separate
 * dimensions and are never conflated (SRS §6).
 */

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export type ScanMode = 'live' | 'demo';

/** FR-004: PHP fingerprinting outcome. */
export type PhpStatus = 'likely' | 'not_detected' | 'inconclusive';
export type PhpDetection = PhpStatus;
export type EvidenceStrength = 'strong' | 'medium' | 'weak';
export interface PhpDetectionAssessment {
  method: 'heuristic';
  calibrated: false;
  explanation: string;
}
export interface PhpEvidence {
  indicator: string;
  value: string;
  strength: EvidenceStrength;
  source: 'header' | 'cookie' | 'url' | 'body';
  explanation: string;
}

/** Potential impact. Independent of evidence strength. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Evidence strength. Independent of impact. */
export type Confidence = 'high' | 'medium' | 'low';

/**
 * CONFIRMED  — evidence directly demonstrates the weakness condition.
 * POTENTIAL  — indicators suggest the weakness; deployment context may mitigate.
 * INCONCLUSIVE — evidence is ambiguous or insufficient to decide.
 */
export type FindingStatus = 'confirmed' | 'potential' | 'inconclusive';

export type FeatureKind =
  | 'form_login'
  | 'form_search'
  | 'form_upload'
  | 'form_generic'
  | 'query_param'
  | 'php_route'
  | 'file_route';

/** Structured evidence attached to every finding (SRS §6 evidence spec). */
export interface Evidence {
  source: string;
  observation: string;
  timestamp: string;
}

/** Normalized snapshot of one HTTP response collected during a scan. */
export interface RawObservation {
  url: string;
  status: number;
  headers: Record<string, string>;
  /** Full Set-Cookie list preserved verbatim (order + attributes matter). */
  setCookies: string[];
  body: string;
  depth: number;
}

export interface PhpDetectionResult {
  status: PhpStatus;
  evidence: PhpEvidence[];
  frameworks: string[];
  phpVersion?: string;
  assessment: PhpDetectionAssessment;
}

export interface FeatureRecord {
  kind: FeatureKind;
  name: string;
  location: string;
  details?: Record<string, unknown>;
}

export interface FindingRecord {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  affectedUrl: string;
  evidence: Evidence[];
  remediation: string;
}

export interface ScanSummary {
  pagesCrawled: number;
  featuresTotal: number;
  findingsTotal: number;
  findingsBySeverity: Record<Severity, number>;
  findingsByStatus: Record<FindingStatus, number>;
  durationMs?: number;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const FEATURE_KIND_LABELS: Record<FeatureKind, string> = {
  form_login: 'Login form',
  form_search: 'Search form',
  form_upload: 'Upload form',
  form_generic: 'Generic form',
  query_param: 'Query parameter',
  php_route: 'PHP route',
  file_route: 'File-handling route',
};
