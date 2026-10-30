import type {
  Confidence,
  Evidence,
  FindingRecord,
  FindingStatus,
  PhpDetectionResult,
  RawObservation,
  Severity,
} from '@/lib/domain/types';
import { createLogger } from '@/lib/core/logger';
import { parseHtml } from '@/lib/scanner/html';
import { analyzeSource, type SourceSignal, type SourceSignalKind } from '@/lib/scanner/source-analyzer';

/**
 * FR-007 — Passive security rules engine.
 *
 * Every rule evaluates ONLY collected observations (headers, cookies, markup)
 * and emits a structured finding with independently assigned
 * severity / confidence / status. No rule sends requests of its own; the
 * engine is purely a function of evidence. Absence of hardening is reported
 * as POTENTIAL (context may mitigate), while direct disclosures and plaintext
 * transport are CONFIRMED conditions.
 */

export interface RuleContext {
  baseUrl: string;
  /** Root (first) observation — primary evidence surface. */
  root: RawObservation;
  /** All observations collected during the bounded crawl. */
  observations: RawObservation[];
  php: PhpDetectionResult;
  /** Source-analysis signals; computed once by runRules when not supplied. */
  signals?: SourceSignal[];
}

export interface RuleEvaluation {
  evidence: Evidence[];
  affectedUrl?: string;
  /** Optional per-evaluation overrides; severity and confidence stay independent. */
  severity?: Severity;
  confidence?: Confidence;
  status?: FindingStatus;
}

export interface PassiveRule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  remediation: string;
  evaluate(ctx: RuleContext): RuleEvaluation | null;
}

function now(): string {
  return new Date().toISOString();
}

function headerEvidence(source: string, observation: string): Evidence {
  return { source, observation, timestamp: now() };
}

function missingOn(root: RawObservation, header: string): boolean {
  return root.headers[header] === undefined || root.headers[header].trim() === '';
}

function parseCookie(cookie: string): { name: string; value: string; attributes: string } {
  const [pair, ...attrs] = cookie.split(';');
  const eq = pair.indexOf('=');
  const name = eq === -1 ? pair.trim() : pair.slice(0, eq).trim();
  const value = eq === -1 ? '' : pair.slice(eq + 1).trim();
  return { name, value, attributes: attrs.map((a) => a.trim()).join('; ') };
}

function hasFlag(attributes: string, flag: RegExp): boolean {
  return flag.test(attributes);
}

function sessionCookies(cookies: string[]): Array<{ raw: string; parsed: ReturnType<typeof parseCookie> }> {
  return cookies
    .map((raw) => ({ raw, parsed: parseCookie(raw) }))
    .filter((c) => /PHPSESSID|session|sess/i.test(c.parsed.name));
}


function signalsOf(ctx: RuleContext, ...kinds: SourceSignalKind[]): SourceSignal[] {
  return (ctx.signals ?? []).filter((s) => kinds.includes(s.kind));
}

function signalEvidence(source: string, signals: SourceSignal[], max = 5): Evidence[] {
  return signals.slice(0, max).map((s) => {
    const location = s.line ? `${s.url}:${s.line}` : s.url;
    const reason = s.meta?.reason ? ` Classification: ${s.meta.reason}` : '';
    const context = s.context ? ` Context: ${s.context}` : '';
    return headerEvidence(source, `${location} — ${s.detail}${reason}${context}`);
  });
}

function firstUrl(signals: SourceSignal[]): string | undefined {
  return signals[0]?.url;
}

const log = createLogger('rules-engine');

export const PASSIVE_RULES: PassiveRule[] = [
  // ---------------------------------------------------------------------------
  // Transport security
  // ---------------------------------------------------------------------------
  {
    id: 'PHP-SEC-TLS-001',
    title: 'Application served over plaintext HTTP',
    description:
      'The target responds over unencrypted HTTP; session tokens and credentials transit the network in cleartext.',
    severity: 'medium',
    confidence: 'high',
    status: 'confirmed',
    remediation:
      'Provision a TLS certificate and enforce HTTPS with a 301 redirect from HTTP; enable HSTS afterwards.',
    evaluate(ctx) {
      if (!ctx.baseUrl.startsWith('http://')) return null;
      return {
        evidence: [
          headerEvidence('url_scheme', `Base URL uses plaintext http:// (${ctx.baseUrl})`),
        ],
      };
    },
  },
  {
    id: 'PHP-SEC-HDR-001',
    title: 'Missing Strict-Transport-Security header',
    description: 'HTTPS responses lack HSTS, allowing downgrade/stripping attacks on first visit.',
    severity: 'medium',
    confidence: 'high',
    status: 'potential',
    remediation:
      "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on the web server.",
    evaluate(ctx) {
      if (!ctx.root.url.startsWith('https://')) return null;
      if (missingOn(ctx.root, 'strict-transport-security')) {
        return {
          evidence: [
            headerEvidence('http_response_header', 'HSTS header absent in HTTPS response'),
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-HDR-002',
    title: 'Missing Content-Security-Policy header',
    description: 'No CSP defined, increasing exposure to injected script execution.',
    severity: 'medium',
    confidence: 'high',
    status: 'potential',
    remediation:
      "Add a Content-Security-Policy header, e.g. \"default-src 'self'; script-src 'self'; object-src 'none'\".",
    evaluate(ctx) {
      if (missingOn(ctx.root, 'content-security-policy')) {
        return {
          evidence: [
            headerEvidence(
              'http_response_header',
              'Content-Security-Policy header not present in response',
            ),
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-HDR-003',
    title: 'Missing X-Content-Type-Options header',
    description: 'Without nosniff, browsers may MIME-sniff responses into executable content.',
    severity: 'low',
    confidence: 'high',
    status: 'potential',
    remediation: "Send 'X-Content-Type-Options: nosniff' on all responses.",
    evaluate(ctx) {
      if (missingOn(ctx.root, 'x-content-type-options')) {
        return {
          evidence: [
            headerEvidence(
              'http_response_header',
              'X-Content-Type-Options header not present in response',
            ),
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-HDR-004',
    title: 'Missing clickjacking protection (X-Frame-Options / frame-ancestors)',
    description: 'No frame-denial directive observed; the UI can potentially be framed for clickjacking.',
    severity: 'low',
    confidence: 'high',
    status: 'potential',
    remediation:
      "Send 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive permitting only trusted origins.",
    evaluate(ctx) {
      const csp = ctx.root.headers['content-security-policy'] ?? '';
      if (missingOn(ctx.root, 'x-frame-options') && !/frame-ancestors/i.test(csp)) {
        return {
          evidence: [
            headerEvidence(
              'http_response_header',
              'Neither X-Frame-Options nor CSP frame-ancestors observed',
            ),
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-HDR-005',
    title: 'Missing Referrer-Policy header',
    description:
      'Referrer policy undefined; full URLs (including parameters) may leak to third-party sites.',
    severity: 'info',
    confidence: 'high',
    status: 'potential',
    remediation: "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).",
    evaluate(ctx) {
      if (missingOn(ctx.root, 'referrer-policy')) {
        return {
          evidence: [
            headerEvidence('http_response_header', 'Referrer-Policy header not present in response'),
          ],
        };
      }
      return null;
    },
  },

  // ---------------------------------------------------------------------------
  // Cookie attributes
  // ---------------------------------------------------------------------------
  {
    id: 'PHP-SEC-CKI-001',
    title: 'Session cookie missing HttpOnly attribute',
    description: 'The session cookie is readable by client-side scripts, enabling exfiltration via XSS.',
    severity: 'medium',
    confidence: 'high',
    status: 'potential',
    remediation:
      "Set 'session.cookie_httponly = 1' in php.ini or issue cookies with the HttpOnly attribute.",
    evaluate(ctx) {
      for (const cookie of sessionCookies(ctx.root.setCookies)) {
        if (!hasFlag(cookie.parsed.attributes, /httponly/i)) {
          return {
            evidence: [
              headerEvidence(
                'http_response_header',
                `Set-Cookie for '${cookie.parsed.name}' lacks HttpOnly (attributes: ${cookie.parsed.attributes || 'none'})`,
              ),
            ],
          };
        }
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-CKI-002',
    title: 'Session cookie missing Secure attribute',
    description: 'The session cookie may be transmitted over unencrypted connections.',
    severity: 'medium',
    confidence: 'high',
    status: 'potential',
    remediation:
      "Set 'session.cookie_secure = 1' in php.ini or issue cookies with the Secure attribute.",
    evaluate(ctx) {
      for (const cookie of sessionCookies(ctx.root.setCookies)) {
        if (!hasFlag(cookie.parsed.attributes, /secure(?:;|$)/i)) {
          return {
            evidence: [
              headerEvidence(
                'http_response_header',
                `Set-Cookie for '${cookie.parsed.name}' lacks Secure (attributes: ${cookie.parsed.attributes || 'none'})`,
              ),
            ],
          };
        }
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-CKI-003',
    title: 'Session cookie missing SameSite attribute',
    description: 'Without SameSite the cookie is sent on cross-site requests, aiding CSRF attacks.',
    severity: 'low',
    confidence: 'high',
    status: 'potential',
    remediation:
      "Set 'session.cookie_samesite = Lax' (or Strict) in php.ini or add the SameSite attribute.",
    evaluate(ctx) {
      for (const cookie of sessionCookies(ctx.root.setCookies)) {
        if (!hasFlag(cookie.parsed.attributes, /samesite/i)) {
          return {
            evidence: [
              headerEvidence(
                'http_response_header',
                `Set-Cookie for '${cookie.parsed.name}' lacks SameSite (attributes: ${cookie.parsed.attributes || 'none'})`,
              ),
            ],
          };
        }
      }
      return null;
    },
  },

  // ---------------------------------------------------------------------------
  // Information disclosure
  // ---------------------------------------------------------------------------
  {
    id: 'PHP-SEC-DSC-001',
    title: 'PHP version disclosed in response headers',
    description: 'The exact PHP version is advertised, letting attackers match known CVEs.',
    severity: 'low',
    confidence: 'high',
    status: 'confirmed',
    remediation: "Set 'expose_php = Off' in php.ini and remove X-Powered-By at the web server.",
    evaluate(ctx) {
      const powered = ctx.root.headers['x-powered-by'];
      if (powered && /PHP[/ ]?\d/i.test(powered)) {
        return {
          evidence: [headerEvidence('http_response_header', `X-Powered-By: ${powered}`)],
        };
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-DSC-002',
    title: 'Framework/version disclosure in markup',
    description:
      'A generator meta tag or framework signature advertises the software stack and version.',
    severity: 'info',
    confidence: 'high',
    status: 'confirmed',
    remediation:
      'Remove generator meta tags and strip framework-specific headers that disclose exact versions.',
    evaluate(ctx) {
      const generator = ctx.root.body.match(
        /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i,
      )?.[1];
      if (generator) {
        return {
          evidence: [headerEvidence('html_meta_generator', `Generator tag: ${generator}`)],
        };
      }
      if (ctx.php.frameworks.length > 0) {
        return {
          evidence: [
            headerEvidence(
              'html_content',
              `Framework signature identifies ${ctx.php.frameworks.join(', ')}`,
            ),
          ],
        };
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-CFG-001',
    title: 'Sensitive configuration path referenced',
    description:
      'Markup references paths commonly exposing configuration or debug data (phpinfo, .env, backups).',
    severity: 'medium',
    confidence: 'medium',
    status: 'potential',
    remediation:
      'Remove debug artifacts (phpinfo pages, .env, backup archives) from the webroot and deny access to dotfiles.',
    evaluate(ctx) {
      const evidence: Evidence[] = [];
      for (const obs of ctx.observations) {
        const matches =
          obs.body.match(
            /(?:href|action|src)=["']([^"']*(?:phpinfo|\.env|\.git(?:[/"]|$)|backup\.(?:zip|tar|sql)|config\.php\.bak)[^"']*)["']/gi,
          ) ?? [];
        if (matches.length > 0) {
          evidence.push(
            headerEvidence(
              'html_content',
              `${obs.url} references sensitive path(s): ${matches.slice(0, 3).join(' | ')}`,
            ),
          );
        }
        if (evidence.length >= 3) break;
      }
      if (evidence.length > 0) {
        return { evidence };
      }
      return null;
    },
  },


  // ---------------------------------------------------------------------------
  // Source analysis (passive — derived from already-collected page source)
  // ---------------------------------------------------------------------------
  {
    id: 'PHP-SEC-SRC-001',
    title: 'Credential or key in the format of a known provider exposed in page source',
    description:
      'Page source contains a string matching a known credential format. Test and documentation context is labeled inconclusive; credential validity is never checked.',
    severity: 'high',
    confidence: 'medium',
    status: 'potential',
    remediation:
      'Revoke and rotate the exposed credential, remove it from client-delivered code, and keep secrets server-side or in a secrets manager.',
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'secret_vendor');
      if (hits.length === 0) return null;
      const confirmedKeyMaterial = hits.some(
        (h) => h.meta?.private_key_material === 'true' && h.meta?.classification === 'confirmed',
      );
      const critical = hits.some(
        (h) => h.meta?.critical === 'true' && h.meta?.private_key_material === 'true' && h.meta?.classification === 'confirmed',
      );
      const allInconclusive = hits.every((h) => h.meta?.classification === 'inconclusive');
      return {
        evidence: signalEvidence('page_source', hits),
        affectedUrl: firstUrl(hits),
        severity: critical ? 'critical' : 'high',
        confidence: critical ? 'high' : 'medium',
        status: confirmedKeyMaterial ? 'confirmed' : allInconclusive ? 'inconclusive' : 'potential',
      };
    },
  },
  {
    id: 'PHP-SEC-SRC-002',
    title: 'Credential-like value assigned in client-side code',
    description:
      'Inline script or comment assigns a literal to a variable named like a password, secret or token. The value may be a placeholder or a public identifier.',
    severity: 'medium',
    confidence: 'low',
    status: 'potential',
    remediation:
      'Do not embed credentials in client code. Move them server-side and use short-lived, scoped tokens for browser use.',
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'secret_generic');
      if (hits.length === 0) return null;
      const allInconclusive = hits.every((h) => h.meta?.classification === 'inconclusive');
      return {
        evidence: signalEvidence('page_source', hits),
        affectedUrl: firstUrl(hits),
        status: allInconclusive ? 'inconclusive' : 'potential',
        confidence: allInconclusive ? 'low' : 'medium',
      };
    },
  },
  {
    id: 'PHP-SEC-SRC-003',
    title: 'PHP error output or filesystem path disclosed',
    description:
      'The response contains PHP warnings, errors or stack traces that reveal server-side file paths and code structure.',
    severity: 'medium',
    confidence: 'high',
    status: 'confirmed',
    remediation:
      "Set 'display_errors = Off' and 'log_errors = On' in production, and handle errors with a generic error page.",
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'php_error');
      if (hits.length === 0) return null;
      return { evidence: signalEvidence('page_source', hits), affectedUrl: firstUrl(hits) };
    },
  },
  {
    id: 'PHP-SEC-SRC-004',
    title: 'Sensitive developer comment left in HTML',
    description:
      'An HTML comment mentions credentials, debug or internal details, or filesystem paths. Comments are delivered to every visitor.',
    severity: 'low',
    confidence: 'medium',
    status: 'potential',
    remediation:
      'Strip HTML comments from production output (build step or template engine) and keep internal notes in the repository.',
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'html_comment');
      if (hits.length === 0) return null;
      return { evidence: signalEvidence('html_comment', hits), affectedUrl: firstUrl(hits) };
    },
  },
  {
    id: 'PHP-SEC-SRC-005',
    title: 'Source map referenced in production page source',
    description:
      'A sourceMappingURL reference may let visitors reconstruct original client source. The map file itself was not requested, so exposure is unverified.',
    severity: 'low',
    confidence: 'medium',
    status: 'potential',
    remediation:
      'Do not publish source maps to production, or restrict them to authenticated users and remove the sourceMappingURL comment.',
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'source_map');
      if (hits.length === 0) return null;
      return { evidence: signalEvidence('page_source', hits), affectedUrl: firstUrl(hits) };
    },
  },
  {
    id: 'PHP-SEC-SRC-006',
    title: 'Third-party resource loaded without Subresource Integrity',
    description:
      'A cross-origin script or stylesheet has no integrity attribute, so a compromise of that host would run attacker code in the page.',
    severity: 'low',
    confidence: 'high',
    status: 'potential',
    remediation:
      "Add 'integrity' and 'crossorigin' attributes to third-party resources, or self-host them.",
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'missing_sri');
      if (hits.length === 0) return null;
      return { evidence: signalEvidence('page_source', hits), affectedUrl: firstUrl(hits) };
    },
  },
  {
    id: 'PHP-SEC-SRC-007',
    title: 'Internal or private host referenced in page source',
    description:
      'Page source links to a private IP address, localhost or an internal-only domain, revealing network layout or leftover development configuration.',
    severity: 'low',
    confidence: 'medium',
    status: 'potential',
    remediation:
      'Remove internal hostnames and addresses from client-delivered code and templates; use environment-specific configuration.',
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'internal_host');
      if (hits.length === 0) return null;
      return { evidence: signalEvidence('page_source', hits), affectedUrl: firstUrl(hits) };
    },
  },
  {
    id: 'PHP-SEC-SRC-008',
    title: 'Client library version with a known advisory',
    description:
      'A referenced JavaScript library version is older than the first release fixing a published advisory. Exploitability depends on how the library is used.',
    severity: 'medium',
    confidence: 'medium',
    status: 'potential',
    remediation: 'Upgrade the library to a supported, patched release and re-test affected pages.',
    evaluate(ctx) {
      const hits = signalsOf(ctx, 'library_version').filter((s) => s.meta?.outdated === 'true');
      if (hits.length === 0) return null;
      return { evidence: signalEvidence('page_source', hits), affectedUrl: firstUrl(hits) };
    },
  },

  // ---------------------------------------------------------------------------
  // Response hygiene
  // ---------------------------------------------------------------------------
  {
    id: 'PHP-SEC-CORS-001',
    title: 'Permissive CORS policy',
    description:
      "Responses allow any origin together with credentials, or allow the 'null' origin, which weakens the same-origin policy.",
    severity: 'medium',
    confidence: 'medium',
    status: 'potential',
    remediation:
      "Reflect only an explicit allow-list of origins, never combine credentials with a wildcard, and do not allow the 'null' origin.",
    evaluate(ctx) {
      const evidence: Evidence[] = [];
      for (const obs of ctx.observations) {
        const origin = obs.headers['access-control-allow-origin']?.trim();
        if (!origin) continue;
        const creds = /^true$/i.test(obs.headers['access-control-allow-credentials']?.trim() ?? '');
        if ((origin === '*' && creds) || origin.toLowerCase() === 'null') {
          evidence.push(
            headerEvidence(
              'http_response_header',
              `${obs.url} sends Access-Control-Allow-Origin: ${origin}${creds ? ' with Access-Control-Allow-Credentials: true' : ''}`,
            ),
          );
        }
        if (evidence.length >= 3) break;
      }
      return evidence.length > 0 ? { evidence, affectedUrl: undefined } : null;
    },
  },
  {
    id: 'PHP-SEC-DSC-003',
    title: 'Directory listing enabled',
    description:
      'A page looks like an automatic web-server directory index, exposing file names and structure.',
    severity: 'medium',
    confidence: 'high',
    status: 'confirmed',
    remediation:
      "Disable directory indexing ('Options -Indexes' on Apache, 'autoindex off' on nginx) or add an index document.",
    evaluate(ctx) {
      const evidence: Evidence[] = [];
      let first: string | undefined;
      for (const obs of ctx.observations) {
        if (/<(?:title|h1)>\s*Index of \//i.test(obs.body)) {
          first ??= obs.url;
          evidence.push(headerEvidence('html_content', `${obs.url} looks like a directory index ("Index of /")`));
        }
        if (evidence.length >= 3) break;
      }
      return evidence.length > 0 ? { evidence, affectedUrl: first } : null;
    },
  },

  // ---------------------------------------------------------------------------
  // Form hygiene (passive — never submits)
  // ---------------------------------------------------------------------------
  {
    id: 'PHP-SEC-FRM-001',
    title: 'Login form without CSRF token field',
    description:
      'A state-changing authentication form exposes no CSRF token field; request forgery may be possible.',
    severity: 'low',
    confidence: 'medium',
    status: 'potential',
    remediation:
      'Include a per-session CSRF token in state-changing forms and verify it server-side.',
    evaluate(ctx) {
      for (const obs of ctx.observations) {
        const forms = parseHtml(obs.body, obs.url).forms;
        const loginForm = forms.find((f) => f.hasPasswordField);
        if (loginForm && !loginForm.csrfTokenField) {
          return {
            evidence: [
              headerEvidence(
                'html_form',
                `Login form at ${loginForm.action ?? obs.url} has no CSRF token field (fields: ${loginForm.fieldNames.join(', ') || 'none'})`,
              ),
            ],
            affectedUrl: obs.url,
          };
        }
      }
      return null;
    },
  },
  {
    id: 'PHP-SEC-FRM-002',
    title: 'Public file upload endpoint discovered',
    description:
      'A publicly reachable upload form was found; unrestricted uploads are a common PHP attack vector.',
    severity: 'info',
    confidence: 'high',
    status: 'potential',
    remediation:
      'Require authentication, validate MIME/extension server-side, store uploads outside the webroot, and randomize stored names.',
    evaluate(ctx) {
      for (const obs of ctx.observations) {
        const forms = parseHtml(obs.body, obs.url).forms;
        const uploadForm = forms.find((f) => f.hasFileField || f.multipart);
        if (uploadForm) {
          return {
            evidence: [
              headerEvidence(
                'html_form',
                `Multipart upload form found at ${uploadForm.action ?? obs.url} (no submission attempted)`,
              ),
            ],
            affectedUrl: uploadForm.action ?? obs.url,
          };
        }
      }
      return null;
    },
  },
]

/**
 * Execute all passive rules against the collected context.
 * Pure function: same evidence in, same findings out (deterministic pipeline).
 */
export function runRules(input: RuleContext): FindingRecord[] {
  const findings: FindingRecord[] = [];
  const ctx: RuleContext = { ...input, signals: input.signals ?? analyzeSource(input.observations) };
  for (const rule of PASSIVE_RULES) {
    try {
      const evaluation = rule.evaluate(ctx);
      if (evaluation && evaluation.evidence.length > 0) {
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: evaluation.severity ?? rule.severity,
          confidence: evaluation.confidence ?? rule.confidence,
          status: evaluation.status ?? rule.status,
          affectedUrl: evaluation.affectedUrl ?? ctx.root.url,
          evidence: evaluation.evidence,
          remediation: rule.remediation,
        });
      }
    } catch (error) {
      // A failing rule must never break the scan — logged and skipped.
      log.warn('rule evaluation failed', {
        ruleId: rule.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return findings;
}
