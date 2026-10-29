/**
 * Scanner configuration constants.
 * Mirrors FR-003: connection timeout 5s, response limit 5MB, max 3 redirects,
 * TLS verification mandatory.
 */
export const SCANNER_CONFIG = {
  /** Per-request connection + response timeout (FR-003). */
  REQUEST_TIMEOUT_MS: 5_000,
  /** Maximum accepted response body size in bytes (FR-003). */
  MAX_RESPONSE_BYTES: 5 * 1024 * 1024,
  /** Maximum redirect hops followed (FR-003). */
  MAX_REDIRECTS: 3,
  /** Crawler bounds (FR-006): same-origin only, bounded depth and page caps. */
  CRAWL_MAX_DEPTH: 2,
  CRAWL_MAX_PAGES: 15,
  /** Only outbound traffic to standard web ports is permitted. */
  ALLOWED_PORTS: [80, 443],
  /** Polite, identifiable User-Agent. Non-destructive scanner. */
  USER_AGENT:
    'PHPFeatureScanner/2.0 (evidence-driven; non-destructive; +safe-passive)',
  /** DNS re-verification window used to detect rebinding during a scan. */
  DNS_RECHECK_MIN_INTERVAL_MS: 1_000,
} as const;

export const PIPELINE_STEPS = [
  'API Request Validation',
  'Network Scope Check',
  'Scan Record Initialization',
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

export const TOTAL_STEPS = PIPELINE_STEPS.length;
