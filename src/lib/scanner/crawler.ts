import { SCANNER_CONFIG } from '@/lib/core/config';
import { safeFetch, SafeFetchError } from '@/lib/core/http-client';
import { createLogger } from '@/lib/core/logger';
import type { RawObservation } from '@/lib/domain/types';
import { normalizeForDedup } from '@/lib/core/url-validation';
import { parseHtml } from './html';

/**
 * FR-006 (discovery half) — Bounded same-origin crawler.
 * Deterministic BFS: depth ≤ CRAWL_MAX_DEPTH, pages ≤ CRAWL_MAX_PAGES,
 * same-origin only, GET only, never submits forms (non-destructive).
 */

const log = createLogger('crawler');

export interface CrawlResult {
  observations: RawObservation[];
  errors: Array<{ url: string; reason: string }>;
}

function isSameOrigin(a: URL, b: URL): boolean {
  return a.protocol === b.protocol && a.hostname === b.hostname && a.port === b.port;
}

export async function crawl(
  startUrl: string,
  opts: { maxDepth?: number; maxPages?: number } = {},
): Promise<CrawlResult> {
  const maxDepth = opts.maxDepth ?? SCANNER_CONFIG.CRAWL_MAX_DEPTH;
  const maxPages = opts.maxPages ?? SCANNER_CONFIG.CRAWL_MAX_PAGES;

  const origin = new URL(startUrl).origin;
  const visited = new Set<string>([normalizeForDedup(new URL(startUrl))]);
  const queue: Array<{ url: string; depth: number }> = [{ url: startUrl, depth: 0 }];
  const observations: RawObservation[] = [];
  const errors: CrawlResult['errors'] = [];

  while (queue.length > 0 && observations.length < maxPages) {
    const item = queue.shift();
    if (!item) break;
    const { url, depth } = item;

    try {
      const result = await safeFetch(url);
      const pageUrl = result.finalUrl;
      // A redirect may land on an already-recorded page — avoid duplicates.
      if (observations.some((o) => o.url === pageUrl)) {
        continue;
      }

      observations.push({
        url: pageUrl,
        status: result.status,
        headers: result.headers,
        setCookies: result.setCookies,
        body: result.body,
        depth,
      });

      if (depth < maxDepth) {
        const parsed = parseHtml(result.body, pageUrl);
        for (const link of parsed.links) {
          if (observations.length + queue.length >= maxPages) break;
          try {
            const linkUrl = new URL(link);
            if (!isSameOrigin(linkUrl, new URL(origin))) continue;
            if (linkUrl.protocol !== 'http:' && linkUrl.protocol !== 'https:') continue;
            const key = normalizeForDedup(linkUrl);
            if (visited.has(key)) continue;
            visited.add(key);
            queue.push({ url: link, depth: depth + 1 });
          } catch {
            // Unparseable link — skip silently.
          }
        }
      }
    } catch (error) {
      const reason =
        error instanceof SafeFetchError || error instanceof Error
          ? error.message
          : 'Unknown crawl error';
      errors.push({ url, reason });
      log.warn('crawl fetch failed', { url, reason });
    }
  }

  log.info('crawl complete', {
    pages: observations.length,
    errors: errors.length,
    maxDepth,
    maxPages,
  });

  return { observations, errors };
}
