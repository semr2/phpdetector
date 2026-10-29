import { z } from 'zod';

/**
 * FR-002 / Pipeline step 1 — API request validation.
 * Strict URL syntax validation before any DNS or network activity.
 */

export class UrlValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UrlValidationError';
  }
}

const TargetUrlSchema = z
  .string()
  .min(1, 'Target URL is required')
  .max(2048, 'Target URL exceeds 2048 characters')
  .refine((v) => {
    try {
      const u = new URL(v);
      return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname.length > 0;
    } catch {
      return false;
    }
  }, 'Must be an absolute http:// or https:// URL')
  .refine((v) => {
    try {
      const u = new URL(v);
      return u.username === '' && u.password === '';
    } catch {
      return false;
    }
  }, 'Must be an absolute http:// or https:// URL')
  .refine((v) => {
    try {
      const u = new URL(v);
      const host = u.hostname.replace(/^\[|\]$/g, '');
      return !/\s/.test(host) && host.includes('.');
    } catch {
      return false;
    }
  }, 'Hostname must be a public domain or IP literal');

export interface ValidatedTarget {
  /** Normalized absolute URL (fragment removed, hash + tracking stripped). */
  url: string;
  scheme: 'http' | 'https';
  host: string;
  port: number;
  origin: string;
}

/** Validate and normalize a scan target URL. Throws UrlValidationError. */
export function validateTargetUrl(raw: string): ValidatedTarget {
  const parsed = TargetUrlSchema.safeParse(raw.trim());
  if (!parsed.success) {
    throw new UrlValidationError(parsed.error.issues[0]?.message ?? 'Invalid URL');
  }

  let url: URL;
  try {
    url = new URL(parsed.data);
  } catch {
    throw new UrlValidationError('Invalid URL');
  }

  url.hash = '';
  const scheme = url.protocol === 'https:' ? 'https' : 'http';
  const explicitPort = url.port ? Number(url.port) : scheme === 'https' ? 443 : 80;

  // Strip default ports for canonical form.
  if ((scheme === 'https' && explicitPort === 443) || (scheme === 'http' && explicitPort === 80)) {
    url.port = '';
  }

  return {
    url: url.toString(),
    scheme,
    host: url.hostname.replace(/^\[|\]$/g, '').toLowerCase(),
    port: explicitPort,
    origin: url.origin,
  };
}

/** Normalize a URL for dedup/crawling: drop fragment, keep query. */
export function normalizeForDedup(url: URL): string {
  const clone = new URL(url.toString());
  clone.hash = '';
  return clone.toString();
}
