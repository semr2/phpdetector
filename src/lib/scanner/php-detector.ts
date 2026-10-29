import type { Evidence, PhpDetectionResult, RawObservation } from '@/lib/domain/types';

/**
 * FR-004 — PHP fingerprinting engine.
 * Combines multi-indicator evidence from headers, cookies, URL morphology and
 * HTML syntax. Correctly handles missing signatures by returning
 * `inconclusive` when evidence is weak/ambiguous and `not_detected` when no
 * indicator fires at all. Detection of PHP is NEVER treated as a vulnerability.
 */

interface FrameworkSignature {
  framework: string;
  pattern: RegExp;
  scope: 'header' | 'cookie' | 'body';
}

const FRAMEWORK_SIGNATURES: FrameworkSignature[] = [
  { framework: 'WordPress', pattern: /wp-content|wp-includes|wp-json/i, scope: 'body' },
  { framework: 'WordPress', pattern: /^WordPress\/?(\d[\d.]*)?/i, scope: 'header' },
  { framework: 'Laravel', pattern: /laravel_session|XSRF-TOKEN/i, scope: 'cookie' },
  { framework: 'Laravel', pattern: /laravel/i, scope: 'header' },
  { framework: 'Symfony', pattern: /symfony/i, scope: 'header' },
  { framework: 'CodeIgniter', pattern: /ci_session/i, scope: 'cookie' },
  { framework: 'CakePHP', pattern: /cakephp/i, scope: 'header' },
  { framework: 'ThinkPHP', pattern: /thinkphp|X-Powered-By:.*ThinkPHP/i, scope: 'header' },
  { framework: 'Yii', pattern: /yiisession|_yii/i, scope: 'cookie' },
  { framework: 'Drupal', pattern: /x-drupal-cache|drupal-settings-json/i, scope: 'header' },
  { framework: 'Joomla', pattern: /^Joomla/i, scope: 'header' },
  { framework: 'Magento', pattern: /magento|PHPSESSID.*Magento/i, scope: 'header' },
  { framework: 'phpMyAdmin', pattern: /phpMyAdmin/i, scope: 'cookie' },
  { framework: 'Slim', pattern: /slim/i, scope: 'header' },
  { framework: 'Zend', pattern: /zend/i, scope: 'header' },
];

const PHP_VERSION_PATTERN = /PHP[/ ]?(\d{1,2}\.\d{1,2}(?:\.\d{1,3})?)/i;
const GENERATOR_PATTERN = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i;

function now(): string {
  return new Date().toISOString();
}

/** Build a synthetic Set-Cookie-like string for framework cookie evidence. */
export function detectPhp(observation: RootObservables): PhpDetectionResult {
  const indicators: PhpDetectionResult['indicators'] = [];
  const evidence: Evidence[] = [];
  let framework: string | undefined;
  let version: string | undefined;

  // 1. X-Powered-By header — strong indicator.
  const poweredBy = observation.headers['x-powered-by'];
  if (poweredBy) {
    const match = poweredBy.match(PHP_VERSION_PATTERN);
    if (match || /php/i.test(poweredBy)) {
      version = version ?? match?.[1];
      indicators.push({ kind: 'strong', detail: `X-Powered-By header discloses PHP (${poweredBy})` });
      evidence.push({
        source: 'http_response_header',
        observation: `X-Powered-By: ${poweredBy}`,
        timestamp: now(),
      });
    }
    const fwMatch = FRAMEWORK_SIGNATURES.find(
      (s) => s.scope === 'header' && s.framework !== 'WordPress' && s.pattern.test(poweredBy),
    );
    if (fwMatch) framework = framework ?? fwMatch.framework;
  }

  // 2. PHPSESSID session cookie — strong indicator.
  const phpsessid = observation.setCookies.find((c) => /PHPSESSID=/i.test(c));
  if (phpsessid) {
    indicators.push({ kind: 'strong', detail: 'PHPSESSID session cookie issued by server' });
    evidence.push({
      source: 'http_response_header',
      observation: `Set-Cookie: ${phpsessid.slice(0, 80)}${phpsessid.length > 80 ? '…' : ''}`,
      timestamp: now(),
    });
  }

  // 3. Framework cookie signatures.
  for (const cookie of observation.setCookies) {
    const fwMatch = FRAMEWORK_SIGNATURES.find((s) => s.scope === 'cookie' && s.pattern.test(cookie));
    if (fwMatch) {
      framework = framework ?? fwMatch.framework;
      indicators.push({
        kind: 'strong',
        detail: `Framework-specific session cookie indicates ${fwMatch.framework}`,
      });
      evidence.push({
        source: 'http_cookie',
        observation: `Set-Cookie signature matches ${fwMatch.framework}`,
        timestamp: now(),
      });
      break;
    }
  }

  // 4. .php URL morphology across fetched locations — medium indicator.
  const phpUrls = observation.urls.filter((u) => /\.php(?:$|[?#])/i.test(u));
  if (phpUrls.length > 0) {
    indicators.push({
      kind: 'medium',
      detail: `${phpUrls.length} location(s) use the .php extension (e.g. ${phpUrls[0]})`,
    });
    evidence.push({
      source: 'url_structure',
      observation: `PHP script extension observed at ${phpUrls.slice(0, 3).join(', ')}`,
      timestamp: now(),
    });
  }

  // 5. HTML body syntax evidence: meta generator, framework paths, form tokens.
  const body = observation.body;
  if (body) {
    const generator = body.match(GENERATOR_PATTERN)?.[1];
    if (generator && /wordpress|drupal|joomla|magento|typo3|php/i.test(generator)) {
      const fwMatch = FRAMEWORK_SIGNATURES.find((s) => s.pattern.test(generator));
      if (fwMatch && !framework) framework = fwMatch.framework;
      indicators.push({ kind: 'medium', detail: `<meta name="generator"> declares "${generator}"` });
      evidence.push({
        source: 'html_meta_generator',
        observation: `Generator meta tag: ${generator}`,
        timestamp: now(),
      });
    }
    for (const sig of FRAMEWORK_SIGNATURES) {
      if (sig.scope === 'body' && sig.pattern.test(body)) {
        if (!framework) {
          framework = sig.framework;
          indicators.push({ kind: 'medium', detail: `HTML content matches ${sig.framework} signatures` });
          evidence.push({
            source: 'html_content',
            observation: `${sig.framework} asset paths or tokens found in markup`,
            timestamp: now(),
          });
        }
        break;
      }
    }
    if (/\.php(?:["'?]|$)/i.test(body)) {
      const hasPhpLinks = /(?:action|href)=["'][^"']*\.php/i.test(body);
      if (hasPhpLinks && !phpUrls.length) {
        indicators.push({ kind: 'medium', detail: 'HTML references .php endpoints (form actions / links)' });
        evidence.push({
          source: 'html_content',
          observation: 'PHP script references found in form actions or anchors',
          timestamp: now(),
        });
      }
    }
  }

  // Decision: strong indicators => likely; no indicators => not_detected; only weak => inconclusive.
  const hasStrong = indicators.some((i) => i.kind === 'strong');
  const hasMedium = indicators.some((i) => i.kind === 'medium');
  let result: PhpDetectionResult['result'];
  if (hasStrong) {
    result = 'likely';
  } else if (hasMedium) {
    result = 'inconclusive';
  } else {
    result = 'not_detected';
  }

  return { result, framework, version, indicators, evidence };
}

/** The observables the detector needs (works for live scans and demo fixtures). */
export interface RootObservables {
  headers: Record<string, string>;
  setCookies: string[];
  urls: string[];
  body: string;
}
