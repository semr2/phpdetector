import type { PhpDetectionResult, PhpEvidence } from '@/lib/domain/types';

/**
 * FR-004 — Heuristic PHP fingerprinting. The status is categorical; this
 * detector does not produce a statistical probability or calibrated score.
 */

const PHP_VERSION_PATTERN = /PHP[/ ]?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)/i;
const GENERATOR_PATTERN = /<meta\b(?=[^>]*\bname=["']generator["'])(?=[^>]*\bcontent=["']([^"']+)["'])[^>]*>/i;

type SignalGroup = 'explicit-php' | 'php-session' | 'php-endpoint' | 'framework' | 'weak';
interface Indicator {
  group: SignalGroup;
  evidence: PhpEvidence;
}

const cleanValue = (value: unknown, max = 160): string => {
  const clean = String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
};

function safeEndpoint(value: string): string | null {
  try {
    const url = new URL(value);
    if (!/\.php$/i.test(url.pathname)) return null;
    // Do not expose query values, fragments, or credentials from URLs.
    return `${url.origin}${url.pathname}`;
  } catch {
    return null;
  }
}

function statusAssessment(status: PhpDetectionResult['status'], groups: Set<SignalGroup>): string {
  if (status === 'likely') {
    if (groups.has('explicit-php')) return 'The response explicitly identifies PHP in X-Powered-By. This is direct disclosure, but remains a heuristic observation.';
    if (groups.has('php-session')) return 'A PHPSESSID cookie was observed. This is a strong PHP heuristic, but the cookie name can be configured or imitated.';
    return 'More than one independent supporting indicator class was observed. The combined evidence suggests PHP, but does not prove it.';
  }
  if (status === 'inconclusive') return 'Only weak, ambiguous, or single supporting evidence was observed; there is not enough evidence to say PHP is likely.';
  return 'No PHP indicators were observed. A server that hides its technology may still use PHP.';
}

/** Missing or malformed input is treated as no observable evidence. */
export function detectPhp(input: RootObservables | null | undefined): PhpDetectionResult {
  const observation = input && typeof input === 'object' ? input : {} as RootObservables;
  const headers = observation.headers && typeof observation.headers === 'object' && !Array.isArray(observation.headers)
    ? observation.headers
    : {};
  const cookies = Array.isArray(observation.setCookies) ? observation.setCookies.filter((v): v is string => typeof v === 'string') : [];
  const urls = Array.isArray(observation.urls) ? observation.urls.filter((v): v is string => typeof v === 'string') : [];
  const body = typeof observation.body === 'string' ? observation.body : '';
  const candidates: Indicator[] = [];
  const frameworks = new Set<string>();
  let phpVersion: string | undefined;

  const add = (group: SignalGroup, indicator: string, value: string, strength: PhpEvidence['strength'], source: PhpEvidence['source'], explanation: string) => {
    candidates.push({ group, evidence: { indicator, value: cleanValue(value), strength, source, explanation } });
  };

  const poweredBy = Object.entries(headers).find(([name]) => name.toLowerCase() === 'x-powered-by')?.[1];
  if (typeof poweredBy === 'string' && /^\s*PHP(?:[/\s]|$)/i.test(poweredBy)) {
    const versionMatch = poweredBy.match(PHP_VERSION_PATTERN);
    phpVersion = versionMatch?.[1];
    add('explicit-php', 'X-Powered-By PHP disclosure', versionMatch?.[0] ?? 'PHP disclosed', 'strong', 'header', 'The response header explicitly names PHP; this is direct technology disclosure.');
  }

  if (cookies.some((cookie) => /(?:^|;\s*)PHPSESSID=/i.test(cookie))) {
    add('php-session', 'PHPSESSID session cookie', 'PHPSESSID', 'strong', 'cookie', 'A common PHP session cookie name was observed; the name can be configured or imitated, so this is not definitive proof.');
  }

  // Framework signatures support PHP identification but do not establish it.
  const frameworkCookies: Array<{ pattern: RegExp; name: string }> = [
    { pattern: /(?:^|;\s*)laravel_session=/i, name: 'Laravel' },
    { pattern: /(?:^|;\s*)ci_session=/i, name: 'CodeIgniter' },
    { pattern: /(?:^|;\s*)(?:yii|_yii)[^=]*=/i, name: 'Yii' },
    { pattern: /(?:^|;\s*)cakephp=/i, name: 'CakePHP' },
  ];
  for (const cookie of cookies) {
    const signature = frameworkCookies.find((candidate) => candidate.pattern.test(cookie));
    if (signature) {
      frameworks.add(signature.name);
      add('framework', `${signature.name} session cookie`, cookie.split('=')[0].split(';')[0], 'medium', 'cookie', 'Framework-specific cookie signature supports PHP identification but is not proof by itself.');
      break;
    }
  }

  if (cookies.some((cookie) => /(?:^|;\s*)XSRF-TOKEN=/i.test(cookie))) {
    add('weak', 'Generic XSRF-TOKEN cookie', 'XSRF-TOKEN', 'weak', 'cookie', 'This cookie is used by many technologies and is only a weak PHP clue.');
  }

  const headerSignatures: Array<{ pattern: RegExp; name: string }> = [
    { pattern: /laravel/i, name: 'Laravel' }, { pattern: /symfony/i, name: 'Symfony' },
    { pattern: /cakephp/i, name: 'CakePHP' }, { pattern: /thinkphp/i, name: 'ThinkPHP' },
    { pattern: /joomla/i, name: 'Joomla' }, { pattern: /drupal/i, name: 'Drupal' },
    { pattern: /magento/i, name: 'Magento' },
  ];
  for (const [header, value] of Object.entries(headers)) {
    if (typeof value !== 'string') continue;
    const signature = headerSignatures.find((candidate) => candidate.pattern.test(value));
    if (signature) {
      frameworks.add(signature.name);
      add('framework', `${signature.name} response marker`, signature.name, 'medium', 'header', `Framework marker in ${cleanValue(header, 60)} supports PHP identification but is not proof.`);
    }
  }

  // Deduplicate canonical endpoint paths. Endpoint count is one supporting
  // evidence class regardless of how many routes or duplicate observations exist.
  const endpoints = new Set(urls.map(safeEndpoint).filter((url): url is string => url !== null));
  if (body && /(?:action|href)=["'][^"']*\.php(?:[?#]|["'])/i.test(body)) {
    // The markup may repeat URLs or include query secrets; record only a generic path clue.
    endpoints.add('HTML .php reference');
  }
  if (endpoints.size > 0) {
    add('php-endpoint', '.php endpoint', [...endpoints].slice(0, 3).join(', '), 'medium', 'url', 'A .php endpoint is a supporting clue, but URL extensions can be routed or imitated by other server technologies.');
  }

  if (body) {
    const generator = body.match(GENERATOR_PATTERN)?.[1];
    if (generator && /wordpress|drupal|joomla|magento|typo3|php/i.test(generator)) {
      const name = /wordpress/i.test(generator) ? 'WordPress' : /drupal/i.test(generator) ? 'Drupal' : /joomla/i.test(generator) ? 'Joomla' : /magento/i.test(generator) ? 'Magento' : /typo3/i.test(generator) ? 'TYPO3' : undefined;
      if (name) frameworks.add(name);
      add('framework', 'Framework generator metadata', name ?? 'PHP-related generator marker', 'medium', 'body', 'Generator metadata is a framework clue; signature specificity varies and it does not prove PHP.');
    }

    const frameworkMarkers: Array<{ pattern: RegExp; name: string }> = [
      { pattern: /wp-content|wp-includes|wp-json/i, name: 'WordPress' },
      { pattern: /drupal-settings-json|\/sites\/default\/files/i, name: 'Drupal' },
      { pattern: /\/media\/catalog\/|mage\/cookies/i, name: 'Magento' },
    ];
    const found = frameworkMarkers.find((signature) => signature.pattern.test(body));
    if (found) {
      frameworks.add(found.name);
      add('framework', `${found.name} markup marker`, found.name, 'medium', 'body', 'Framework-specific markup supports PHP identification but is not proof by itself.');
    }
  }

  // Keep each unique indicator for reporting, but count each evidence class
  // at most once. Repeated pages, URLs, or framework markers do not add weight.
  const seen = new Set<string>();
  const evidence = candidates.flatMap(({ evidence: item }) => {
    const key = `${item.source}|${item.indicator}|${item.value}`;
    if (seen.has(key)) return [];
    seen.add(key);
    return [item];
  });
  const groups = new Set(candidates.map((candidate) => candidate.group));
  const status: PhpDetectionResult['status'] = groups.has('explicit-php') || groups.has('php-session') ||
    (groups.has('php-endpoint') && groups.has('framework'))
    ? 'likely'
    : groups.size > 0
      ? 'inconclusive'
      : 'not_detected';

  return {
    status,
    evidence,
    frameworks: [...frameworks],
    phpVersion,
    assessment: {
      method: 'heuristic',
      calibrated: false,
      explanation: statusAssessment(status, groups),
    },
  };
}

/** The observables the detector needs (works for live scans and demo fixtures). */
export interface RootObservables {
  headers: Record<string, string>;
  setCookies: string[];
  urls: string[];
  body: string;
}
