import type { RawObservation } from '@/lib/domain/types';

/**
 * Source analysis (passive).
 *
 * Inspects the page source ALREADY collected by the crawler (HTML, inline
 * scripts, comments). It never issues requests: linked scripts and source
 * maps are only *referenced*, never fetched, and discovered endpoints are
 * listed, never probed. The module is a pure function of its input so it can
 * be unit-tested without a network, database or framework.
 *
 * Secrets are masked at the point of detection — raw values never leave this
 * module, so they cannot reach the database, the API or the HTML report.
 */

export type SourceSignalKind =
  | 'secret_vendor'
  | 'secret_generic'
  | 'html_comment'
  | 'php_error'
  | 'source_map'
  | 'missing_sri'
  | 'internal_host'
  | 'library_version';

export interface SourceSignal {
  kind: SourceSignalKind;
  /** Page the signal was observed on. */
  url: string;
  /** Human-readable, already masked/truncated description. */
  detail: string;
  /** One-based line number in fetched source, when available. */
  line?: number;
  /** Short source excerpt with credential-like values redacted. */
  context?: string;
  /** Optional extra attributes (e.g. library name/version, advisory). */
  meta?: Record<string, string>;
}

/** Hard caps keep analysis bounded regardless of page size or content. */
export const SOURCE_LIMITS = {
  MAX_BODY_CHARS: 1_000_000,
  MAX_SIGNALS_PER_KIND: 25,
  MAX_DETAIL_CHARS: 160,
} as const;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Mask a sensitive value: first 4 chars + length. Never returns the full value. */
export function maskSecret(value: string): string {
  const head = value.slice(0, 4);
  return `${head}… (${value.length} chars)`;
}

function truncate(value: string, max: number = SOURCE_LIMITS.MAX_DETAIL_CHARS): string {
  const flat = value.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

function safeUrl(value: string, base: string): URL | null {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

function credentialSourceUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return value.split(/[?#]/, 1)[0];
  }
}

/** Return the contents of every inline <script> block (no src attribute). */
interface SourceScope { text: string; offset: number }

function inlineScripts(html: string): SourceScope[] {
  const out: SourceScope[] = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    if (/\bsrc\s*=/i.test(m[1])) continue;
    if (m[2].trim()) out.push({ text: m[2], offset: m.index + m[0].indexOf(m[2]) });
  }
  return out;
}

function htmlComments(html: string): SourceScope[] {
  const out: SourceScope[] = [];
  const re = /<!--([\s\S]{0,2000}?)-->/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const text = m[1];
    // Skip IE conditional comments and downlevel-revealed markers.
    if (/^\s*\[if\b|^\s*<!\[endif\]|^\s*\[endif\]/i.test(text)) continue;
    out.push({ text, offset: m.index + m[0].indexOf(text) });
  }
  return out;
}

/** Code blocks commonly used for documentation examples. */
function codeExamples(html: string): SourceScope[] {
  const out: SourceScope[] = [];
  const re = /<(pre|code)\b([^>]*)>([\s\S]*?)<\/\1\s*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    if (m[3].trim()) out.push({ text: m[3], offset: m.index + m[0].indexOf(m[3]) });
  }
  return out;
}

// ---------------------------------------------------------------------------
// secrets
// ---------------------------------------------------------------------------

interface VendorPattern {
  label: string;
  pattern: RegExp;
  /** Private-key markers can be elevated when full key material is observed. */
  critical?: boolean;
}

const VENDOR_PATTERNS: VendorPattern[] = [
  { label: 'AWS access key ID', pattern: /\b(AKIA[0-9A-Z]{16})\b/g },
  { label: 'Google API key', pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { label: 'Stripe live secret key', pattern: /\b(sk_live_[0-9a-zA-Z]{16,})\b/g },
  { label: 'GitHub token', pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,})\b/g },
  { label: 'Slack token', pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  {
    label: 'Private key block',
    pattern: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g,
    critical: true,
  },
  {
    label: 'JSON Web Token',
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  },
];

const GENERIC_ASSIGNMENT =
  /\b(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|passwd|password|db[_-]?pass)\b["']?\s*[:=]\s*["']([^"'\s]{8,64})["']/gi;

const PLACEHOLDER =
  /^(?:your|my|xxx|replace[_-]?me|changeme|change[_-]?me|example|sample|test|dummy|placeholder|fake|redacted|null|undefined|true|false|\*+|<|\{\{|\$\{|%)/i;

const EXACT_PLACEHOLDERS = new Set([
  'AKIAIOSFODNN7EXAMPLE', 'your_api_key', 'replace_me', 'example_secret',
  'test_password', 'xxxxxxxx',
]);

function placeholderReason(value: string): string | null {
  if (EXACT_PLACEHOLDERS.has(value)) return 'Recognized documentation or test placeholder.';
  if (PLACEHOLDER.test(value)) return 'Value is explicitly labeled as an example, test, or placeholder.';
  if (/^(.)\1+$/.test(value) || /^[*xX.#-]{6,}$/.test(value)) return 'Value uses a repeated-character placeholder pattern.';
  if (value.length >= 8 && new Set(value.toLowerCase()).size < 3) return 'Value has too little character variety and resembles a placeholder.';
  return null;
}

function hasVendorPlaceholderMarker(value: string): boolean {
  const payload = value.replace(/^(?:sk_live_|AKIA|AIza|gh[pousr]_|xox[baprs]-)/i, '');
  return /^(?:example|sample|placeholder|test|dummy|fake|replace[_-]?me)/i.test(payload) ||
    /(?:^|[-_])(?:example|sample|placeholder|test|dummy|fake|replace[_-]?me)(?:[-_]|$)/i.test(payload);
}

function hasCompletePrivateKeyMaterial(scope: string, offset: number): boolean {
  const match = scope.slice(offset).match(
    /-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----([\s\S]{30,8000}?)-----END \1-----/,
  );
  if (!match) return false;
  const payload = match[2].replace(/\s+/g, '');
  return payload.length >= 64 && payload.length % 4 === 0 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(payload) && new Set(payload).size >= 12;
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function sourceLine(starts: number[], index: number): number {
  let low = 0;
  let high = starts.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (starts[mid] <= index) low = mid + 1;
    else high = mid;
  }
  return low;
}

function isDocumentationContext(url: string, excerpt: string): boolean {
  let path = '';
  try { path = new URL(url).pathname; } catch { path = url; }
  const fileContext = /(?:^|[/. _-])(tests?|fixtures?|examples?|demos?|docs?|documentation)(?=$|[/. _-])/i.test(path);
  const textContext = /\b(?:examples?|samples?|fixtures?|tests?|testing|demos?|placeholder|documentation|docs?|do not use|not a real credential)\b/i.test(excerpt);
  return fileContext || textContext;
}

function detectSecrets(url: string, scope: string, out: SourceSignal[], starts = lineStarts(scope), baseOffset = 0): void {
  for (const vp of VENDOR_PATTERNS) {
    vp.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = vp.pattern.exec(scope)) !== null) {
      const placeholder = placeholderReason(m[1]);
      if (placeholder) continue;
      const excerpt = scope.slice(Math.max(0, m.index - 70), Math.min(scope.length, m.index + m[0].length + 70));
      const markedPlaceholder = hasVendorPlaceholderMarker(m[1]);
      const contextual = isDocumentationContext(url, excerpt) || markedPlaceholder;
      const pemMaterial = Boolean(vp.critical && hasCompletePrivateKeyMaterial(scope, m.index));
      const shown = vp.critical ? vp.label : `${vp.label}: ${maskSecret(m[1])}`;
      out.push({
        kind: 'secret_vendor',
        url: credentialSourceUrl(url),
        detail: shown,
        line: sourceLine(starts, baseOffset + m.index),
        context: truncate(redactEvidenceContext(excerpt), 120),
        meta: {
          label: vp.label,
          critical: vp.critical ? 'true' : 'false',
          private_key_material: pemMaterial ? 'true' : 'false',
          classification: contextual
            ? 'inconclusive'
            : vp.critical
              ? pemMaterial ? 'confirmed' : 'inconclusive'
              : 'potential',
          reason: contextual
            ? markedPlaceholder
              ? 'Credential-shaped value contains an example or test marker; retained as inconclusive for review.'
              : 'Credential-shaped text appears in documentation, test, fixture, or example context; retained for review.'
            : vp.critical && !pemMaterial
              ? 'Only a private-key header marker was found; complete key material was not observed.'
              : vp.critical
                ? 'A complete private-key-shaped block is present in fetched source; cryptographic validity was not checked.'
              : 'Provider-specific credential format matched; validity was not checked.',
        },
      });
    }
  }
}

function detectGenericSecrets(url: string, scope: string, out: SourceSignal[], starts = lineStarts(scope), baseOffset = 0): void {
  GENERIC_ASSIGNMENT.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = GENERIC_ASSIGNMENT.exec(scope)) !== null) {
    const value = m[2];
    if (placeholderReason(value)) continue;
    const excerptStart = Math.max(0, m.index - 70);
    const excerptEnd = Math.min(scope.length, m.index + m[0].length + 70);
    const excerpt = scope.slice(excerptStart, excerptEnd);
    const contextual = isDocumentationContext(url, excerpt);
    out.push({
      kind: 'secret_generic',
      url: credentialSourceUrl(url),
      detail: `${m[1].toLowerCase()} assigned a literal value: ${maskSecret(value)}`,
      line: sourceLine(starts, baseOffset + m.index),
      context: truncate(redactEvidenceContext(excerpt), 120),
      meta: {
        name: m[1].toLowerCase(),
        classification: contextual ? 'inconclusive' : 'potential',
        reason: contextual
          ? 'Credential-like assignment appears in documentation, test, fixture, or example context; retained for review.'
          : 'A value is assigned to a credential-related variable; its validity was not checked.',
      },
    });
  }
}

// ---------------------------------------------------------------------------
// comments
// ---------------------------------------------------------------------------

const COMMENT_HINT =
  /\b(password|passwd|credential|secret|api[_-]?key|token|todo|fixme|hack|debug|staging|internal|admin|backdoor|temporary|remove before)\b|\/(?:var|home|usr|etc|srv)\/[\w./-]+|[A-Za-z]:\\[\w\\.-]+/i;

function maskKnownSecrets(text: string): string {
  let masked = text.replace(
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|$)/g,
    (block) => `[PRIVATE KEY MATERIAL REDACTED (${block.length} chars)]`,
  );
  for (const vp of VENDOR_PATTERNS) {
    // Do not share a global RegExp instance with detectSecrets: replace() resets
    // lastIndex, which otherwise restarts its outer detection loop forever.
    const pattern = new RegExp(vp.pattern.source, vp.pattern.flags);
    masked = masked.replace(pattern, (_all, g1: string) => maskSecret(g1));
  }
  return masked.replace(
    new RegExp(GENERIC_ASSIGNMENT.source, 'gi'),
    (_all, name: string, value: string) => `${name}=${maskSecret(value)}`,
  );
}

function redactEvidenceContext(text: string): string {
  // Bound each candidate string. The previous escaped-string expression could
  // backtrack exponentially on hostile source ending with an unmatched quote.
  return maskKnownSecrets(text).replace(/(["'])([^"'\\]{0,256})\1/g, (literal) => {
    const quote = literal[0];
    const value = literal.slice(1, -1);
    return `${quote}${value ? maskSecret(value) : ''}${quote}`;
  });
}

// ---------------------------------------------------------------------------
// PHP errors / path disclosure
// ---------------------------------------------------------------------------

const PHP_ERROR_HTML =
  /<b>(Warning|Notice|Fatal error|Parse error|Deprecated)<\/b>:\s*([^<]{1,160}?)\s+in\s+<b>([^<]{1,200})<\/b>\s+on line\s+<b>(\d+)<\/b>/gi;
const PHP_ERROR_TEXT =
  /\b(Warning|Notice|Fatal error|Parse error|Deprecated): ([^\n<]{1,160}?) in ((?:\/|[A-Za-z]:\\)[^\s:<]{1,200}) on line (\d+)/g;
const PHP_STACK_TRACE = /Stack trace:\s*#0\s+((?:\/|[A-Za-z]:\\)[^\s(]{1,200})/g;

function detectPhpErrors(url: string, body: string, out: SourceSignal[]): void {
  for (const re of [PHP_ERROR_HTML, PHP_ERROR_TEXT]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      out.push({
        kind: 'php_error',
        url,
        detail: `${m[1]} in ${m[3]} on line ${m[4]}`,
        meta: { path: m[3], type: m[1] },
      });
    }
  }
  PHP_STACK_TRACE.lastIndex = 0;
  let t: RegExpExecArray | null;
  while ((t = PHP_STACK_TRACE.exec(body)) !== null) {
    out.push({
      kind: 'php_error',
      url,
      detail: `PHP stack trace discloses path ${t[1]}`,
      meta: { path: t[1], type: 'stack_trace' },
    });
  }
}

// ---------------------------------------------------------------------------
// source maps, SRI, internal hosts
// ---------------------------------------------------------------------------

function detectSourceMaps(url: string, body: string, out: SourceSignal[]): void {
  const re = /(?:\/\/|\/\*)[#@]\s*sourceMappingURL=([^\s*]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) {
    const ref = m[1];
    out.push({
      kind: 'source_map',
      url,
      detail: ref.startsWith('data:')
        ? 'Inline (data:) source map embedded in page source'
        : `Source map referenced: ${truncate(ref, 120)}`,
    });
  }
}

function detectMissingSri(url: string, html: string, out: SourceSignal[]): void {
  const pageOrigin = safeUrl(url, url)?.origin;
  const tagRe = /<(script|link)\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  while ((m = tagRe.exec(html)) !== null) {
    const tag = m[1].toLowerCase();
    const attrs = m[2];
    const ref =
      tag === 'script'
        ? attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i)?.[1]
        : /\brel\s*=\s*["']?stylesheet/i.test(attrs)
          ? attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1]
          : undefined;
    if (!ref) continue;
    const resolved = safeUrl(ref, url);
    if (!resolved || !/^https?:$/.test(resolved.protocol)) continue;
    if (resolved.origin === pageOrigin) continue;
    if (/\bintegrity\s*=/i.test(attrs)) continue;
    out.push({
      kind: 'missing_sri',
      url,
      detail: `Third-party ${tag === 'script' ? 'script' : 'stylesheet'} without integrity attribute: ${truncate(resolved.toString(), 120)}`,
      meta: { host: resolved.host },
    });
  }
}

const PRIVATE_IP_URL =
  /\bhttps?:\/\/((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})|localhost)(?::\d{2,5})?(?:[/"'\s?#,;)\]>]|$)/gi;
const INTERNAL_TLD_URL =
  /\bhttps?:\/\/((?:[a-z0-9-]+\.)+(?:internal|intranet|corp|lan|home\.arpa|local))(?::\d{2,5})?(?:[/"'\s?#,;)\]>]|$)/gi;

function detectInternalHosts(url: string, body: string, out: SourceSignal[]): void {
  const ownHost = safeUrl(url, url)?.hostname.toLowerCase();
  const seen = new Set<string>();
  for (const re of [PRIVATE_IP_URL, INTERNAL_TLD_URL]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      const host = m[1].toLowerCase();
      // A site referencing itself is not a disclosure (e.g. a .local dev target).
      if (host === ownHost || seen.has(host)) continue;
      seen.add(host);
      out.push({
        kind: 'internal_host',
        url,
        detail: `Internal or private host referenced in page source: ${host}`,
        meta: { host },
      });
    }
  }
}

// ---------------------------------------------------------------------------
// library versions
// ---------------------------------------------------------------------------

interface LibAdvisory {
  name: string;
  /** First version that is NOT affected. */
  fixedIn: string;
  advisory: string;
}

/** Deliberately small, high-confidence table. Extend with care. */
const LIB_ADVISORIES: LibAdvisory[] = [
  { name: 'jquery', fixedIn: '3.5.0', advisory: 'CVE-2020-11022 / CVE-2020-11023 (XSS)' },
  { name: 'bootstrap', fixedIn: '3.4.1', advisory: 'CVE-2019-8331 (XSS, 3.x line)' },
  { name: 'moment', fixedIn: '2.29.4', advisory: 'CVE-2022-31129 (ReDoS)' },
  { name: 'lodash', fixedIn: '4.17.21', advisory: 'CVE-2021-23337 (command injection)' },
];

const LIB_REF =
  /(?:^|[/@._-])(jquery|bootstrap|moment|lodash)(?:\.min)?[-@./]?v?(\d+\.\d+(?:\.\d+)?)(?=[./\-@?#"']|$)/i;

export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

function detectLibraries(url: string, html: string, out: SourceSignal[]): void {
  const re = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi;
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const hit = m[1].match(LIB_REF);
    if (!hit) continue;
    const name = hit[1].toLowerCase();
    const version = hit[2];
    const key = `${name}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const adv = LIB_ADVISORIES.find((a) => a.name === name);
    // Bootstrap 4.x is affected until 4.3.1; keep the table simple and exact.
    const fixed = adv
      ? name === 'bootstrap' && compareVersions(version, '4.0.0') >= 0
        ? '4.3.1'
        : adv.fixedIn
      : undefined;
    const outdated = adv && fixed ? compareVersions(version, fixed) < 0 : false;
    out.push({
      kind: 'library_version',
      url,
      detail: outdated
        ? `${name} ${version} is below ${fixed} — ${adv!.advisory}`
        : `${name} ${version} referenced`,
      meta: { name, version, outdated: outdated ? 'true' : 'false', advisory: adv?.advisory ?? '' },
    });
  }
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

function dedupe(signals: SourceSignal[]): SourceSignal[] {
  const positions = new Map<string, number>();
  const perKind = new Map<SourceSignalKind, number>();
  const out: SourceSignal[] = [];
  for (const s of signals) {
    const credential = s.kind === 'secret_vendor' || s.kind === 'secret_generic';
    const identity = credential ? (s.meta?.label ?? s.meta?.name ?? '') : '';
    const key = `${s.kind}|${s.url}|${identity}|${s.detail}`;
    const priorIndex = positions.get(key);
    if (priorIndex !== undefined) {
      const prior = out[priorIndex];
      // If the same masked value occurs in ordinary page code as well as an
      // example context, retain the less ambiguous evidence for human review.
      if (credential && prior.meta?.classification === 'inconclusive' && s.meta?.classification === 'potential') {
        out[priorIndex] = { ...prior, line: s.line ?? prior.line, context: s.context ?? prior.context, meta: s.meta };
      }
      continue;
    }
    const count = perKind.get(s.kind) ?? 0;
    if (count >= SOURCE_LIMITS.MAX_SIGNALS_PER_KIND) continue;
    perKind.set(s.kind, count + 1);
    positions.set(key, out.length);
    out.push({ ...s, detail: truncate(s.detail) });
  }
  return out;
}

/**
 * Analyse the source of every collected observation. Pure and deterministic:
 * same input → same signals, in the same order.
 */
export function analyzeSource(observations: RawObservation[]): SourceSignal[] {
  const signals: SourceSignal[] = [];

  for (const obs of observations) {
    const body = obs.body.slice(0, SOURCE_LIMITS.MAX_BODY_CHARS);
    if (!body) continue;

    const scripts = inlineScripts(body);
    const comments = htmlComments(body);
    const examples = codeExamples(body);
    const lines = lineStarts(body);

    // Vendor-format secrets: anywhere in the source.
    detectSecrets(obs.url, body, signals, lines);
    // Generic key=value assignments: only where code/config actually lives.
    for (const script of scripts) detectGenericSecrets(obs.url, script.text, signals, lines, script.offset);
    for (const comment of comments) detectGenericSecrets(obs.url, comment.text, signals, lines, comment.offset);
    for (const example of examples) detectGenericSecrets(obs.url, example.text, signals, lines, example.offset);

    for (const comment of comments) {
      if (!COMMENT_HINT.test(comment.text)) continue;
      signals.push({
        kind: 'html_comment',
        url: obs.url,
        detail: `Comment: ${truncate(maskKnownSecrets(comment.text), 120)}`,
      });
    }

    detectPhpErrors(obs.url, body, signals);
    detectSourceMaps(obs.url, body, signals);
    detectMissingSri(obs.url, body, signals);
    detectInternalHosts(obs.url, body, signals);
    detectLibraries(obs.url, body, signals);
  }

  return dedupe(signals);
}
