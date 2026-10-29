import * as cheerio from 'cheerio';

/**
 * HTML parsing utilities (Parsing layer). Uses BeautifulSoup4-equivalent
 * Cheerio for robust, selector-based parsing instead of fragile regex.
 */

export interface ParsedPage {
  title: string;
  links: string[]; // resolved absolute URLs
  forms: ParsedForm[];
}

export interface ParsedForm {
  method: string;
  action: string | null; // resolved absolute URL, null = same URL
  fieldNames: string[];
  hasPasswordField: boolean;
  hasFileField: boolean;
  multipart: boolean;
  csrfTokenField: string | null;
}

const CSRF_HINTS = /^(csrf|_csrf|csrftoken|_token|authenticity_token|nonce|__requestverificationtoken)$/i;
const SEARCH_HINTS = /^(q|s|search|query|keyword|keywords|term)$/i;

function resolve(base: string, value: string): string | null {
  try {
    const trimmed = value.trim();
    if (!trimmed || trimmed.startsWith('javascript:') || trimmed.startsWith('data:') || trimmed.startsWith('mailto:') || trimmed.startsWith('tel:')) {
      return null;
    }
    return new URL(trimmed, base).toString();
  } catch {
    return null;
  }
}

export function parseHtml(html: string, baseUrl: string): ParsedPage {
  const $ = cheerio.load(html);
  const title = $('title').first().text().trim() || baseUrl;

  const links: string[] = [];
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (!href) return;
    const resolved = resolve(baseUrl, href);
    if (resolved) links.push(resolved);
  });

  const forms: ParsedForm[] = [];
  $('form').each((_, el) => {
    const $form = $(el);
    const method = ($form.attr('method') ?? 'GET').toUpperCase();
    const rawAction = $form.attr('action');
    const action = rawAction ? resolve(baseUrl, rawAction) : null;
    const enctype = ($form.attr('enctype') ?? '').toLowerCase();

    const fieldNames: string[] = [];
    let hasPasswordField = false;
    let hasFileField = false;
    let csrfTokenField: string | null = null;

    $form.find('input, select, textarea, button[type="submit"][name]').each((__, field) => {
      const $field = $(field);
      const type = ($field.attr('type') ?? 'text').toLowerCase();
      const name = $field.attr('name');
      if (type === 'password') hasPasswordField = true;
      if (type === 'file') hasFileField = true;
      if (name) {
        if (!fieldNames.includes(name)) fieldNames.push(name);
        if (CSRF_HINTS.test(name) || /csrf/i.test(name)) csrfTokenField = name;
      }
    });

    forms.push({
      method,
      action,
      fieldNames,
      hasPasswordField,
      hasFileField,
      multipart: enctype.includes('multipart') || hasFileField,
      csrfTokenField,
    });
  });

  return { title, links, forms };
}

/** Extract query-parameter names from a URL. */
export function extractQueryParamNames(url: string): string[] {
  try {
    const parsed = new URL(url);
    return [...new Set([...parsed.searchParams.keys()])];
  } catch {
    return [];
  }
}

/** Does a parameter name look like a search input? */
export function looksLikeSearchParam(name: string): boolean {
  return SEARCH_HINTS.test(name);
}

/** Extract <title> quickly for page records. */
export function extractTitle(html: string): string | null {
  try {
    const $ = cheerio.load(html);
    const t = $('title').first().text().trim();
    return t ? t.slice(0, 200) : null;
  } catch {
    return null;
  }
}
