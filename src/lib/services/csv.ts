import type { FindingRecord } from '@/lib/domain/types';

/**
 * CSV cell escaping. Cells that start with =, +, - or @ (or a tab/CR) are
 * prefixed with an apostrophe so spreadsheet apps never evaluate evidence text
 * as a formula (CSV/formula injection).
 */
export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** One row per finding; evidence is flattened into a single cell. */
export function buildFindingsCsv(
  findings: FindingRecord[],
  options: { simulated?: boolean; simulationNotice?: string } = {},
): string {
  const header = ['rule_id', 'title', 'severity', 'confidence', 'status', 'affected_url', 'evidence', 'remediation'];
  if (options.simulated) header.unshift('data_origin', 'record_type', 'notice');
  const rows = findings.map((f) => {
    const values = [
      f.ruleId,
      f.title,
      f.severity,
      f.confidence,
      f.status,
      f.affectedUrl,
      f.evidence.map((e) => `[${e.source}] ${e.observation}`).join(' | '),
      f.remediation,
    ];
    if (options.simulated) values.unshift('SIMULATED DEMO DATA', 'finding', '');
    return values.map(csvCell).join(',');
  });
  if (options.simulated && rows.length === 0) {
    rows.push([
      'SIMULATED DEMO DATA',
      'metadata',
      options.simulationNotice ?? 'No live website was scanned; this CSV contains no findings.',
      ...Array(header.length - 3).fill(''),
    ].map(csvCell).join(','));
  }
  return [header.join(','), ...rows].join('\r\n') + '\r\n';
}
