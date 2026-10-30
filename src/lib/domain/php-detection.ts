import type { PhpDetectionResult, PhpEvidence, PhpStatus } from './types';

const VALID_STATUSES: PhpStatus[] = ['likely', 'not_detected', 'inconclusive'];
const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function legacySource(value: unknown): PhpEvidence['source'] {
  const source = String(value ?? '').toLowerCase();
  if (source.includes('header') || source.includes('cookie')) return source.includes('cookie') ? 'cookie' : 'header';
  if (source.includes('url') || source.includes('structure')) return 'url';
  return 'body';
}

/** Normalize current and historical database values without exposing old percentages. */
export function normalizePhpDetection(
  raw: unknown,
  fallbackStatus: string | null,
  fallbackFramework: string | null,
): PhpDetectionResult {
  const stored = Array.isArray(raw) ? null : isRecord(raw) ? raw : null;
  const statusValue = stored?.status ?? stored?.result ?? fallbackStatus;
  const status: PhpStatus = VALID_STATUSES.includes(statusValue as PhpStatus)
    ? statusValue as PhpStatus
    : 'inconclusive';

  const evidence: PhpEvidence[] = [];
  const oldEvidence = stored?.evidence;
  if (Array.isArray(oldEvidence)) {
    for (const entry of oldEvidence) {
      if (!isRecord(entry)) continue;
      if (
        typeof entry.indicator === 'string' && typeof entry.value === 'string' &&
        (entry.strength === 'strong' || entry.strength === 'medium' || entry.strength === 'weak') &&
        (entry.source === 'header' || entry.source === 'cookie' || entry.source === 'url' || entry.source === 'body') &&
        typeof entry.explanation === 'string'
      ) {
        evidence.push({
          indicator: entry.indicator,
          value: entry.value,
          strength: entry.strength,
          source: entry.source,
          explanation: entry.explanation,
        });
      } else {
        // Prior versions stored {source, observation, timestamp} records.
        evidence.push({
          indicator: typeof entry.source === 'string' ? entry.source : 'Legacy PHP indicator',
          value: typeof entry.observation === 'string' ? entry.observation : '',
          strength: 'weak',
          source: legacySource(entry.source),
          explanation: 'Legacy evidence format; its strength was not recorded.',
        });
      }
    }
  }

  const frameworks = Array.isArray(stored?.frameworks)
    ? stored!.frameworks.filter((value): value is string => typeof value === 'string')
    : typeof stored?.framework === 'string'
      ? [stored.framework]
      : fallbackFramework
        ? fallbackFramework.split(',').map((value) => value.trim()).filter(Boolean)
        : [];
  const oldAssessment = isRecord(stored?.assessment) ? stored.assessment : null;
  const explanation = typeof oldAssessment?.explanation === 'string'
    ? oldAssessment.explanation
    : `Historical ${status} result normalized to the heuristic model. Its detection method was not calibrated.`;

  return {
    status,
    evidence,
    frameworks,
    ...(typeof stored?.phpVersion === 'string'
      ? { phpVersion: stored.phpVersion }
      : typeof stored?.version === 'string'
        ? { phpVersion: stored.version }
        : {}),
    assessment: { method: 'heuristic', calibrated: false, explanation },
  };
}
