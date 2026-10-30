import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSource, compareVersions, maskSecret } from '../src/lib/scanner/source-analyzer.ts';

const obs = (body: string, url = 'https://shop.example/index.php') => ({
  url,
  status: 200,
  headers: {},
  setCookies: [],
  body,
  depth: 0,
});

const kinds = (body: string, url?: string) => analyzeSource([obs(body, url)]).map((s) => s.kind);

test('vendor-format keys are detected and masked', () => {
  const key = 'AKIA1234567890ABCDEF';
  const signals = analyzeSource([obs(`<script>var k = "${key}";</script>`)]);
  const hit = signals.find((s) => s.kind === 'secret_vendor');
  assert.ok(hit);
  assert.ok(!hit.detail.includes(key), 'raw key must never appear in the signal');
  assert.match(hit.detail, /AKIA… \(20 chars\)/);
});

test('private key header alone is inconclusive and does not expose material', () => {
  const [hit] = analyzeSource([obs('<!-- -----BEGIN RSA PRIVATE KEY----- -->')]).filter(
    (s) => s.kind === 'secret_vendor',
  );
  assert.equal(hit.meta?.critical, 'true');
  assert.equal(hit.meta?.private_key_material, 'false');
  assert.equal(hit.meta?.classification, 'inconclusive');
  assert.ok(!hit.context?.includes('BEGIN RSA PRIVATE KEY'));
});

test('generic assignments need real-looking values and script/comment scope', () => {
  assert.ok(kinds(`<script>const api_key = "9fA3kLm2Qx7Zp1Wd";</script>`).includes('secret_generic'));
  assert.ok(!kinds(`<script>const api_key = "your_api_key_here";</script>`).includes('secret_generic'));
  assert.ok(!kinds(`<script>var password = "xxxxxxxx";</script>`).includes('secret_generic'));
  // Plain page text outside script/comment is not scanned for generic assignments.
  assert.ok(!kinds(`<p>password = "9fA3kLm2Qx7Zp1Wd"</p>`).includes('secret_generic'));
});

test('weak but real-looking passwords are still reported', () => {
  assert.ok(kinds(`<script>var password = "password123";</script>`).includes('secret_generic'));
});

test('secrets inside comments are masked in the comment signal', () => {
  const signals = analyzeSource([obs('<!-- TODO remove: api_key="9fA3kLm2Qx7Zp1Wd" -->')]);
  const comment = signals.find((s) => s.kind === 'html_comment');
  assert.ok(comment);
  assert.ok(!comment.detail.includes('9fA3kLm2Qx7Zp1Wd'));
});

test('benign and conditional comments are ignored', () => {
  assert.ok(!kinds('<!-- main navigation -->').includes('html_comment'));
  assert.ok(!kinds('<!--[if lt IE 9]><script src="/html5.js"></script><![endif]-->').includes('html_comment'));
});

test('PHP errors and stack traces disclose paths', () => {
  const html = `<br /><b>Warning</b>:  mysqli_connect(): Access denied in <b>/var/www/html/db.php</b> on line <b>12</b><br />`;
  const hit = analyzeSource([obs(html)]).find((s) => s.kind === 'php_error');
  assert.equal(hit?.meta?.path, '/var/www/html/db.php');
  const text = 'Fatal error: Uncaught Exception: x in /srv/app/index.php on line 9';
  assert.ok(kinds(text).includes('php_error'));
  assert.ok(kinds('Stack trace:\n#0 /srv/app/lib.php(4): run()').includes('php_error'));
});

test('source maps: referenced and inline', () => {
  assert.ok(kinds('<script>var a=1;\n//# sourceMappingURL=app.js.map</script>').includes('source_map'));
  const inline = analyzeSource([obs('<script>//# sourceMappingURL=data:application/json;base64,AAAA</script>')]);
  assert.match(inline.find((s) => s.kind === 'source_map')!.detail, /Inline/);
});

test('SRI: only cross-origin resources without integrity are flagged', () => {
  const html = `
    <script src="https://cdn.other.com/a.js"></script>
    <script src="https://cdn.other.com/b.js" integrity="sha384-abc" crossorigin="anonymous"></script>
    <script src="/local.js"></script>
    <script src="https://shop.example/same-origin.js"></script>
    <link rel="stylesheet" href="https://fonts.other.com/x.css">
    <link rel="icon" href="https://cdn.other.com/favicon.ico">`;
  const hits = analyzeSource([obs(html)]).filter((s) => s.kind === 'missing_sri');
  assert.equal(hits.length, 2);
});

test('internal hosts are flagged, but a site referencing itself is not', () => {
  const html = `<script>fetch("http://10.0.4.12:8080/api"); fetch("https://db.corp/x");</script>`;
  const hosts = analyzeSource([obs(html)]).filter((s) => s.kind === 'internal_host').map((s) => s.meta?.host);
  assert.deepEqual(hosts.sort(), ['10.0.4.12', 'db.corp']);
  // .local dev targets referencing their own host must not self-report.
  const own = analyzeSource([obs('<a href="http://demo.shoplite.local/x">x</a>', 'http://demo.shoplite.local/')]);
  assert.ok(!own.some((s) => s.kind === 'internal_host'));
  // Bare version-like numbers are not URLs.
  assert.ok(!kinds('<p>Release 10.0.0.1 notes</p>').includes('internal_host'));
});

test('library versions: outdated vs patched', () => {
  const html = `
    <script src="/js/jquery-1.12.4.min.js"></script>
    <script src="https://cdn.example/jquery@3.7.1/dist/jquery.min.js" integrity="x"></script>
    <script src="/assets/bootstrap-4.1.0.min.js"></script>
    <script src="/assets/bootstrap-4.6.2.min.js"></script>`;
  const libs = analyzeSource([obs(html)]).filter((s) => s.kind === 'library_version');
  const by = (n: string, v: string) => libs.find((s) => s.meta?.name === n && s.meta?.version === v);
  assert.equal(by('jquery', '1.12.4')?.meta?.outdated, 'true');
  assert.equal(by('jquery', '3.7.1')?.meta?.outdated, 'false');
  assert.equal(by('bootstrap', '4.1.0')?.meta?.outdated, 'true');
  assert.equal(by('bootstrap', '4.6.2')?.meta?.outdated, 'false');
});

test('version comparison', () => {
  assert.equal(compareVersions('3.5.0', '3.5'), 0);
  assert.equal(compareVersions('1.12.4', '3.5.0'), -1);
  assert.equal(compareVersions('2.29.4', '2.29.3'), 1);
});

test('output is deterministic, deduplicated and bounded', () => {
  const body = '<script src="https://cdn.other.com/a.js"></script>'.repeat(100);
  const a = analyzeSource([obs(body)]);
  const b = analyzeSource([obs(body)]);
  assert.deepEqual(a, b);
  assert.equal(a.filter((s) => s.kind === 'missing_sri').length, 1);
  const many = Array.from({ length: 200 }, (_, i) => `<script src="https://h${i}.example/a.js"></script>`).join('');
  assert.equal(analyzeSource([obs(many)]).filter((s) => s.kind === 'missing_sri').length, 25);
});

test('large hostile input stays fast (no catastrophic backtracking)', () => {
  const evil = '<!--' + 'a'.repeat(50_000) + '<script>' + 'x = "'.repeat(20_000);
  const start = Date.now();
  analyzeSource([obs(evil)]);
  assert.ok(Date.now() - start < 2000);
});

test('mask helper never returns the full value', () => {
  assert.equal(maskSecret('abcdef123456'), 'abcd… (12 chars)');
});

test('common placeholder API keys and password values are ignored', () => {
  const values = ['your_api_key', 'replace_me', 'example_secret', 'test_password', 'xxxxxxxx'];
  for (const value of values) {
    const signals = analyzeSource([obs(`<script>const api_key = "${value}";</script>`)])
      .filter((signal) => signal.kind === 'secret_generic' || signal.kind === 'secret_vendor');
    assert.equal(signals.length, 0, value);
  }
  const awsExample = analyzeSource([obs('<script>const id = "AKIAIOSFODNN7EXAMPLE";</script>')]);
  assert.equal(awsExample.filter((signal) => signal.kind === 'secret_vendor').length, 0);
});

test('example passwords are ignored when explicitly labeled', () => {
  const signals = analyzeSource([obs('<script>const password = "example_password_value";</script>')]);
  assert.equal(signals.filter((signal) => signal.kind === 'secret_generic').length, 0);
});

test('vendor-shaped example credentials are retained as inconclusive, not confirmed', () => {
  const token = 'sk_live_example1234567890abcdef';
  const hit = analyzeSource([obs(`<script>const token = "${token}";</script>`)]).find(
    (signal) => signal.kind === 'secret_vendor',
  );
  assert.ok(hit);
  assert.equal(hit.meta?.classification, 'inconclusive');
  assert.match(hit.meta?.reason ?? '', /example or test marker/i);
  assert.ok(!JSON.stringify(hit).includes(token));
});

test('credential-like values in test fixtures remain reviewable as inconclusive', () => {
  const observation = obs(
    '<script>\nconst client_secret = "aB93xK7pQ2vL8mN4";\n</script>',
    'https://shop.example/tests/fixture.html',
  );
  const hit = analyzeSource([observation]).find((signal) => signal.kind === 'secret_generic');
  assert.ok(hit);
  assert.equal(hit.meta?.classification, 'inconclusive');
  assert.equal(hit.line, 2);
  assert.equal(hit.url, observation.url);
  assert.match(hit.meta?.reason ?? '', /retained for review/i);
});

test('documentation examples retain realistic credentials with inconclusive context', () => {
  const html = '<pre><code>const access_token = "aB93xK7pQ2vL8mN4";</code></pre>';
  const hit = analyzeSource([obs(html, 'https://shop.example/docs/api')]).find((signal) => signal.kind === 'secret_generic');
  assert.ok(hit);
  assert.equal(hit.meta?.classification, 'inconclusive');
});

test('credential-shaped vendor and generic values are reported with a reason', () => {
  const token = 'sk_live_1234567890abcdefghijkl';
  const html = `<script>const api_key = "aB93xK7pQ2vL8mN4"; const stripe = "${token}";</script>`;
  const signals = analyzeSource([obs(html)]).filter((signal) => signal.kind.startsWith('secret_'));
  assert.equal(signals.length, 2);
  for (const signal of signals) {
    assert.equal(signal.meta?.classification, 'potential');
    assert.ok(signal.meta?.reason);
  }
});

test('unassigned random strings are not treated as generic credentials', () => {
  const signals = analyzeSource([obs('<p>random value: aB93xK7pQ2vL8mN4</p>')]);
  assert.equal(signals.filter((signal) => signal.kind === 'secret_generic').length, 0);
});

test('credential findings are deduplicated by masked value while retaining a line', () => {
  const value = 'aB93xK7pQ2vL8mN4';
  const html = `<script>const api_key = "${value}";\nconst api_key = "${value}";</script>`;
  const signals = analyzeSource([obs(html)]).filter((signal) => signal.kind === 'secret_generic');
  assert.equal(signals.length, 1);
  assert.equal(signals[0].line, 1);
});

test('credential values and PEM material are redacted from all signal fields', () => {
  const secret = 'aB93xK7pQ2vL8mN4';
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${'A'.repeat(90)}\n-----END RSA PRIVATE KEY-----`;
  const signals = analyzeSource([obs(
    `<script>const password = "${secret}";</script><!-- ${pem} -->`,
    'https://shop.example/page?api_key=query-secret-value',
  )]);
  const keySignal = signals.find((signal) => signal.kind === 'secret_vendor' && signal.meta?.label === 'Private key block');
  assert.equal(keySignal?.meta?.private_key_material, 'false');
  assert.equal(keySignal?.meta?.classification, 'inconclusive');
  const serialized = JSON.stringify(signals);
  assert.ok(!serialized.includes(secret));
  assert.ok(!serialized.includes('A'.repeat(30)));
  assert.ok(!serialized.includes('query-secret-value'));
  assert.ok(serialized.includes('REDACTED'));
});

test('complete diverse PEM-shaped material can be classified as confirmed exposure', () => {
  const payload = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.repeat(2);
  const pem = `-----BEGIN RSA PRIVATE KEY-----\n${payload}\n-----END RSA PRIVATE KEY-----`;
  const hit = analyzeSource([obs(`<!-- ${pem} -->`)]).find(
    (signal) => signal.kind === 'secret_vendor' && signal.meta?.label === 'Private key block',
  );
  assert.ok(hit);
  assert.equal(hit.meta?.private_key_material, 'true');
  assert.equal(hit.meta?.classification, 'confirmed');
  assert.ok(!JSON.stringify(hit).includes(payload));
});

test('internal hosts are found when followed by punctuation', () => {
  const html = '<!-- staging db at http://10.0.4.12:3306, see also https://git.corp; ok -->';
  const hosts = analyzeSource([obs(html)]).filter((s) => s.kind === 'internal_host').map((s) => s.meta?.host);
  assert.deepEqual(hosts.sort(), ['10.0.4.12', 'git.corp']);
});
