import type { FeatureRecord, RawObservation } from '@/lib/domain/types';
import { extractQueryParamNames, looksLikeSearchParam, parseHtml } from './html';

/**
 * FR-006 — Feature discovery. Classifies forms (login, search, upload),
 * query parameters, PHP routes and file-handling routes from already-fetched
 * content only. Form values are NEVER submitted (non-destructive guarantee).
 */
export function extractFeatures(observations: RawObservation[]): FeatureRecord[] {
  const features: FeatureRecord[] = [];
  const seen = new Set<string>();

  const push = (feature: FeatureRecord) => {
    const key = `${feature.kind}|${feature.location}|${feature.name}`;
    if (seen.has(key)) return;
    seen.add(key);
    features.push(feature);
  };

  for (const obs of observations) {
    const parsed = parseHtml(obs.body, obs.url);

    // ---- Form classification -------------------------------------------------
    for (const form of parsed.forms) {
      const location = form.action ?? obs.url;

      if (form.hasPasswordField) {
        push({
          kind: 'form_login',
          name: 'Login / authentication form',
          location,
          details: {
            method: form.method,
            fields: form.fieldNames.slice(0, 12),
            hasCsrfField: form.csrfTokenField !== null,
            csrfFieldName: form.csrfTokenField,
          },
        });
      } else if (form.hasFileField || form.multipart) {
        push({
          kind: 'form_upload',
          name: 'File upload form',
          location,
          details: {
            method: form.method,
            enctype: 'multipart/form-data',
            fields: form.fieldNames.slice(0, 12),
          },
        });
      } else if (form.fieldNames.some((f) => looksLikeSearchParam(f))) {
        push({
          kind: 'form_search',
          name: 'Search form',
          location,
          details: {
            method: form.method,
            fields: form.fieldNames.slice(0, 12),
          },
        });
      } else {
        push({
          kind: 'form_generic',
          name: `Form (${form.method})`,
          location,
          details: {
            method: form.method,
            fields: form.fieldNames.slice(0, 12),
          },
        });
      }
    }

    // ---- Query parameters ----------------------------------------------------
    for (const name of extractQueryParamNames(obs.url)) {
      push({
        kind: 'query_param',
        name: `Parameter “${name}”`,
        location: obs.url,
        details: { parameter: name, looksLikeSearch: looksLikeSearchParam(name) },
      });
    }

    // ---- PHP routes ----------------------------------------------------------
    if (/\.php(?:$|[?#])/i.test(obs.url)) {
      push({
        kind: 'php_route',
        name: obs.url.split('/').pop()?.split('?')[0] || obs.url,
        location: obs.url,
      });
    }
    for (const link of parsed.links) {
      try {
        const linkUrl = new URL(link);
        if (/\.php$/i.test(linkUrl.pathname)) {
          push({
            kind: 'php_route',
            name: linkUrl.pathname.split('/').pop() || '/',
            location: link,
          });
        }
        if (/(upload|file|download|import|attach|media)/i.test(linkUrl.pathname)) {
          push({
            kind: 'file_route',
            name: linkUrl.pathname,
            location: link,
          });
        }
      } catch {
        // ignore malformed links
      }
    }
  }

  return features;
}
