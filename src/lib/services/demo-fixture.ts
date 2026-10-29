import type { RawObservation } from '@/lib/domain/types';

/**
 * Demo fixture — a deterministic, offline stand-in for a fictional PHP app
 * ("ShopLite PHP Cart") used to exercise the full pipeline without network
 * access (sandbox-safe self-test, mirrors the SRS integration-test intent).
 * The fixture only feeds the SAME fingerprint/feature/rule code paths as a
 * live scan — no separate evaluation logic exists for demo mode.
 */

const BASE = 'http://demo.shoplite.local';

export const DEMO_BASE_URL = BASE;

export function buildDemoObservations(): RawObservation[] {
  const rootHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ShopLite — PHP Cart Demo</title>
  <meta name="generator" content="WordPress 5.8.1">
</head>
<body>
  <h1>ShopLite</h1>
  <nav>
    <a href="${BASE}/about.php">About</a>
    <a href="${BASE}/search.php">Search</a>
    <a href="${BASE}/login.php">Login</a>
    <a href="${BASE}/upload.php">Media</a>
    <a href="${BASE}/uploads/browse.php">Browse uploads</a>
  </nav>
  <form action="${BASE}/search.php" method="GET">
    <input type="text" name="q" placeholder="Search products">
    <button type="submit">Go</button>
  </form>
  <footer><a href="${BASE}/phpinfo.php">System info (admin)</a></footer>
</body>
</html>`;

  const loginHtml = `<!DOCTYPE html>
<html><head><title>Login — ShopLite</title></head>
<body>
  <form action="${BASE}/login.php" method="POST">
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">Sign in</button>
  </form>
</body></html>`;

  const searchHtml = `<!DOCTYPE html>
<html><head><title>Search — ShopLite</title></head>
<body>
  <form action="${BASE}/search.php" method="GET">
    <input type="text" name="q">
    <button type="submit">Go</button>
  </form>
  <p>No results.</p>
</body></html>`;

  const uploadHtml = `<!DOCTYPE html>
<html><head><title>Media — ShopLite</title></head>
<body>
  <form action="${BASE}/upload.php" method="POST" enctype="multipart/form-data">
    <input type="file" name="asset">
    <button type="submit">Upload</button>
  </form>
</body></html>`;

  const aboutHtml = `<!DOCTYPE html>
<html><head><title>About — ShopLite</title></head>
<body><p>ShopLite is a demo store.</p><a href="${BASE}/index.php">Home</a></body></html>`;

  return [
    {
      url: `${BASE}/`,
      status: 200,
      headers: {
        'server': 'Apache/2.4.41 (Ubuntu)',
        'x-powered-by': 'PHP/7.4.33',
        'content-type': 'text/html; charset=UTF-8',
      },
      setCookies: ['PHPSESSID=8f14e45fceea167a5a36dedd4bea2543; path=/'],
      body: rootHtml,
      depth: 0,
    },
    {
      url: `${BASE}/login.php`,
      status: 200,
      headers: { 'content-type': 'text/html; charset=UTF-8' },
      setCookies: [],
      body: loginHtml,
      depth: 1,
    },
    {
      url: `${BASE}/search.php`,
      status: 200,
      headers: { 'content-type': 'text/html; charset=UTF-8' },
      setCookies: [],
      body: searchHtml,
      depth: 1,
    },
    {
      url: `${BASE}/upload.php`,
      status: 200,
      headers: { 'content-type': 'text/html; charset=UTF-8' },
      setCookies: [],
      body: uploadHtml,
      depth: 1,
    },
    {
      url: `${BASE}/about.php`,
      status: 200,
      headers: { 'content-type': 'text/html; charset=UTF-8' },
      setCookies: [],
      body: aboutHtml,
      depth: 1,
    },
  ];
}
