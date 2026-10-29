import { SCANNER_CONFIG } from './config';
import { createLogger } from './logger';
import { assertHostInScope, ScopeViolationError } from './network-scope';
import { validateTargetUrl, UrlValidationError } from './url-validation';

/**
 * FR-003 — Controlled HTTP communication.
 *  - Connection timeout 5s
 *  - Response limit 5MB (Content-Length pre-check + streamed cap)
 *  - Max 3 redirects, every hop re-validated against the network scope policy
 *  - TLS verification mandatory (system trust store; never disabled)
 */

const log = createLogger('http-client');

export class SafeFetchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SafeFetchError';
  }
}

export interface SafeFetchResult {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  bytes: number;
  redirected: boolean;
  redirectChain: string[];
  elapsedMs: number;
}

interface SafeFetchOptions {
  method?: 'GET';
  maxRedirects?: number;
  timeoutMs?: number;
  maxBytes?: number;
}

function headersToRecord(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return; // handled via getSetCookie
    out[key.toLowerCase()] = value;
  });
  return out;
}

function collectSetCookies(headers: Headers): string[] {
  const getter = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getter === 'function') {
    return getter.call(headers);
  }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

async function fetchSingle(
  url: string,
  timeoutMs: number,
  maxBytes: number,
): Promise<{ response: Response; bytes: number; body: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'user-agent': SCANNER_CONFIG.USER_AGENT,
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.8',
      },
      // TLS verification is mandatory and cannot be turned off here.
    });

    const declaredLength = Number(response.headers.get('content-length') ?? '0');
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      await response.body?.cancel();
      throw new SafeFetchError(
        `Response body exceeds ${maxBytes} byte limit (Content-Length: ${declaredLength})`,
      );
    }

    const reader = response.body?.getReader();
    if (!reader) {
      return { response, bytes: 0, body: '' };
    }

    const chunks: Uint8Array[] = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        received += value.byteLength;
        if (received > maxBytes) {
          await reader.cancel();
          throw new SafeFetchError(
            `Response body exceeds ${maxBytes} byte limit while streaming`,
          );
        }
        chunks.push(value);
      }
    }

    const merged = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const body = new TextDecoder('utf-8', { fatal: false }).decode(merged);
    return { response, bytes: received, body };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Perform a scope-validated, size- and time-bounded GET request.
 * Throws UrlValidationError | ScopeViolationError | SafeFetchError.
 */
export async function safeFetch(rawUrl: string, options: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const maxRedirects = options.maxRedirects ?? SCANNER_CONFIG.MAX_REDIRECTS;
  const timeoutMs = options.timeoutMs ?? SCANNER_CONFIG.REQUEST_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? SCANNER_CONFIG.MAX_RESPONSE_BYTES;

  const startedAt = Date.now();
  const chain: string[] = [];
  let currentUrl = rawUrl;
  let redirected = false;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    // Step 2 of pipeline re-applied to every hop (DNS rebinding + redirect safety).
    const target = validateTargetUrl(currentUrl);
    await assertHostInScope(target.host);
    chain.push(target.url);

    const { response, bytes, body } = await fetchSingle(target.url, timeoutMs, maxBytes);

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (location) {
        if (hop === maxRedirects) {
          throw new SafeFetchError(`Redirect limit of ${maxRedirects} exceeded`);
        }
        const next = new URL(location, target.url).toString();
        log.info('following redirect', { from: target.url, to: next, status: response.status });
        currentUrl = next;
        redirected = true;
        continue;
      }
    }

    return {
      finalUrl: target.url,
      status: response.status,
      headers: headersToRecord(response.headers),
      setCookies: collectSetCookies(response.headers),
      body,
      bytes,
      redirected,
      redirectChain: chain,
      elapsedMs: Date.now() - startedAt,
    };
  }

  throw new SafeFetchError(`Redirect limit of ${maxRedirects} exceeded`);
}

/** Re-export for orchestrator use. */
export { ScopeViolationError, UrlValidationError };
