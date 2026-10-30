import type {
  Evidence,
  FindingRecord,
  FeatureRecord,
  PhpDetectionResult,
  ScanSummary,
} from '@/lib/domain/types';
import { FEATURE_KIND_LABELS, type FeatureKind } from '@/lib/domain/types';
export { buildFindingsCsv, csvCell } from './csv';

/**
 * Report generation (SRS §5 step 11). Produces:
 *  - JSON: canonical machine-readable assessment report
 *  - HTML: standalone, self-contained document with strict output escaping
 *    (all interpolated values pass through escapeHtml before rendering) and
 *    print-ready CSS so the browser's "Save as PDF" produces a clean PDF.
 */

export interface ReportInput {
  id: string;
  targetUrl: string;
  mode: 'live' | 'demo';
  status: string;
  createdAt: string;
  completedAt?: string;
  /** Optional fixed generation timestamp for deterministic fixture reports. */
  generatedAt?: string;
  /** Explicit notice used by simulated reports. */
  simulationNotice?: string;
  php: PhpDetectionResult;
  summary: ScanSummary;
  pages: Array<{ url: string; httpStatus: number; depth: number }>;
  features: FeatureRecord[];
  findings: FindingRecord[];
  crawlErrors?: Array<{ url: string; reason: string }>;
}

export function buildReportJson(input: ReportInput): Record<string, unknown> {
  return {
    report: {
      generator: 'PHP Feature & Vulnerability Detection System 2.0',
      generatedAt: input.generatedAt ?? new Date().toISOString(),
      scan: {
        id: input.id,
        targetUrl: input.targetUrl,
        mode: input.mode,
        status: input.status,
        createdAt: input.createdAt,
        completedAt: input.completedAt ?? null,
      },
      phpDetection: {
        status: input.php.status,
        frameworks: input.php.frameworks,
        phpVersion: input.php.phpVersion ?? null,
        evidence: input.php.evidence,
        assessment: input.php.assessment,
      },
      summary: input.summary,
      pages: input.pages,
      features: input.features.map((f) => ({
        kind: f.kind,
        label: FEATURE_KIND_LABELS[f.kind as FeatureKind] ?? f.kind,
        name: f.name,
        location: f.location,
        details: f.details ?? null,
      })),
      findings: input.findings.map((f) => ({
        rule_id: f.ruleId,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        status: f.status,
        affected_url: f.affectedUrl,
        evidence: f.evidence,
        remediation: f.remediation,
      })),
      crawlErrors: input.crawlErrors ?? [],
      ...(input.mode === 'demo'
        ? {
            simulated: true,
            simulationNotice:
              input.simulationNotice ?? 'SIMULATED DEMO DATA — no live website was scanned. Example findings are not confirmed vulnerabilities.',
          }
        : {}),
    },
  };
}

/** Escape every untrusted value before HTML interpolation (SRS §9). */
export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#b91c1c',
  high: '#c2410c',
  medium: '#a16207',
  low: '#4d7c0f',
  info: '#475569',
};

const STATUS_COLOR: Record<string, string> = {
  confirmed: '#15803d',
  potential: '#a16207',
  inconclusive: '#64748b',
};

export function buildReportHtml(input: ReportInput): string {
  const e = escapeHtml;
  const sevRows = Object.entries(input.summary.findingsBySeverity)
    .map(([k, v]) => `${e(k)}: <strong>${e(v)}</strong>`)
    .join(' &nbsp;·&nbsp; ');

  const findingsHtml = input.findings
    .map(
      (f) => `
  <article class="finding">
    <div class="finding-head">
      <span class="chip" style="background:${SEVERITY_COLOR[f.severity] ?? '#64748b'}">${e(f.severity)}</span>
      <span class="chip outline">${e(f.status)}</span>
      <span class="chip outline">confidence: ${e(f.confidence)}</span>
      <span class="rule-id">${e(f.ruleId)}</span>
    </div>
    <h3>${e(f.title)}</h3>
    <p class="affected">Affected: ${e(f.affectedUrl)}</p>
    <ul class="evidence">
      ${f.evidence
        .map(
          (ev: Evidence) =>
            `<li><code>${e(ev.source)}</code> — ${e(ev.observation)}<span class="ts">${e(ev.timestamp)}</span></li>`,
        )
        .join('\n      ')}
    </ul>
    <p class="remediation"><strong>Remediation:</strong> ${e(f.remediation)}</p>
  </article>`,
    )
    .join('\n');

  const featuresHtml = input.features
    .map(
      (f) => `
    <tr>
      <td>${e(FEATURE_KIND_LABELS[f.kind as FeatureKind] ?? f.kind)}</td>
      <td>${e(f.name)}</td>
      <td class="mono">${e(f.location)}</td>
    </tr>`,
    )
    .join('\n');

  const pagesHtml = input.pages
    .map(
      (p) =>
        `<tr><td class="mono">${e(p.url)}</td><td>${e(p.httpStatus)}</td><td>${e(p.depth)}</td></tr>`,
    )
    .join('\n');

  const phpEvidenceHtml = input.php.evidence
    .map((ev) => `<li><strong>${e(ev.indicator)}</strong> (${e(ev.strength)}, ${e(ev.source)}) — ${e(ev.value)}<br>${e(ev.explanation)}</li>`)
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assessment Report — ${e(input.targetUrl)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
         margin: 0; background: #f8fafc; color: #0f172a; line-height: 1.55; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 32px 20px 64px; }
  header.report { border-bottom: 3px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 19px; margin: 32px 0 12px; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }
  h3 { margin: 8px 0; font-size: 16px; }
  .meta { color: #475569; font-size: 13px; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge.likely { background: #166534; color: #fff; }
  .badge.not_detected { background: #334155; color: #fff; }
  .badge.inconclusive { background: #a16207; color: #fff; }
  .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px 18px; margin: 12px 0; }
  .statgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin: 14px 0; }
  .stat { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px; text-align: center; }
  .stat .num { font-size: 22px; font-weight: 700; }
  .stat .lbl { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: .04em; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eef2f7; vertical-align: top; word-break: break-all; }
  th { background: #f1f5f9; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #475569; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .finding { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px 16px; margin: 12px 0; }
  .finding-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 6px; }
  .chip { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #fff; text-transform: uppercase; letter-spacing: .03em; }
  .chip.outline { background: transparent; color: #334155; border: 1px solid #cbd5e1; text-transform: none; }
  .rule-id { margin-left: auto; font-family: ui-monospace, monospace; font-size: 12px; color: #64748b; }
  .affected { font-size: 13px; color: #475569; }
  .evidence { margin: 8px 0 10px; padding-left: 18px; font-size: 13px; }
  .evidence code { background: #f1f5f9; border-radius: 4px; padding: 1px 5px; font-size: 11px; }
  .evidence .ts { color: #94a3b8; font-size: 11px; margin-left: 6px; }
  .remediation { font-size: 13px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 8px 12px; }
  ul { margin: 6px 0; }
  .note { font-size: 12px; color: #64748b; }
  .simulation-banner { border: 2px solid #b45309; background: #fffbeb; color: #78350f; border-radius: 8px; padding: 12px 14px; margin: 16px 0; font-weight: 700; }
  footer { margin-top: 40px; border-top: 1px solid #cbd5e1; padding-top: 12px; font-size: 12px; color: #64748b; }
  @media print {
    body { background: #fff; }
    .wrap { padding: 0; max-width: none; }
    .finding, .card, table { break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="report">
    <h1>PHP Feature &amp; Vulnerability Assessment Report</h1>
    <p class="meta">
      Target: <strong>${e(input.targetUrl)}</strong>
      &nbsp;|&nbsp; Scan ID: <span class="mono">${e(input.id)}</span>
      &nbsp;|&nbsp; Mode: ${e(input.mode)}
      <br>Completed: ${e(input.completedAt ?? input.createdAt)}
      &nbsp;|&nbsp; PHP detection:
      <span class="badge ${e(input.php.status)}">${e(input.php.status)}</span>
      ${input.php.frameworks.length ? `&nbsp;|&nbsp; Stack: <strong>${e(input.php.frameworks.join(', '))}</strong>` : ''}
      ${input.php.phpVersion ? ` (${e(input.php.phpVersion)})` : ''}
    </p>
    <p class="note">Evidence-driven assessment. A technology or feature alone is never reported as a vulnerability; findings are backed by the observations listed below.</p>
  </header>
  ${input.mode === 'demo' ? `<div class="simulation-banner">${e(input.simulationNotice ?? 'SIMULATED DEMO DATA — no live website was scanned. Example findings are not confirmed vulnerabilities.')}</div>` : ''}

  <h2>Executive Summary</h2>
  <div class="statgrid">
    <div class="stat"><div class="num">${e(input.summary.pagesCrawled)}</div><div class="lbl">Pages</div></div>
    <div class="stat"><div class="num">${e(input.summary.featuresTotal)}</div><div class="lbl">Features</div></div>
    <div class="stat"><div class="num">${e(input.summary.findingsTotal)}</div><div class="lbl">Findings</div></div>
    <div class="stat"><div class="num">${e(input.summary.findingsBySeverity.high + input.summary.findingsBySeverity.critical)}</div><div class="lbl">High+ findings</div></div>
  </div>
  <p class="meta">By severity — ${sevRows}</p>

  <h2>PHP Fingerprinting</h2>
  <div class="card">
    <p><strong>Result:</strong> <span class="badge ${e(input.php.status)}">${e(input.php.status)}</span></p>
    <p class="note">${e(input.php.assessment.explanation)} (Heuristic; not calibrated.)</p>
    <ul class="evidence">${phpEvidenceHtml || '<li>No PHP indicators observed.</li>'}</ul>
  </div>

  <h2>Findings (${e(input.findings.length)})</h2>
  ${findingsHtml || '<p class="note">No findings produced by the passive rule set.</p>'}

  <h2>Feature Inventory (${e(input.features.length)})</h2>
  <table>
    <thead><tr><th>Type</th><th>Name</th><th>Location</th></tr></thead>
    <tbody>${featuresHtml || '<tr><td colspan="3">No features discovered.</td></tr>'}</tbody>
  </table>

  <h2>Crawled Pages (${e(input.pages.length)})</h2>
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>Depth</th></tr></thead>
    <tbody>${pagesHtml}</tbody>
  </table>

  ${(input.crawlErrors?.length ?? 0) > 0 ? `
  <h2>Crawl Notices</h2>
  <table><tbody>${(input.crawlErrors ?? [])
    .map((c) => `<tr><td class="mono">${e(c.url)}</td><td>${e(c.reason)}</td></tr>`)
    .join('')}</tbody></table>` : ''}

  <footer>
    Generated by PHP Feature &amp; Vulnerability Detection System — evidence-driven, non-destructive, passive assessment.
    Severity describes potential impact; confidence describes evidence strength. To export as PDF, print this page.
  </footer>
</div>
</body>
</html>`;
}
