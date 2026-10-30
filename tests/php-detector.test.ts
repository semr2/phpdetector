import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectPhp, type RootObservables } from '../src/lib/scanner/php-detector.ts';

const input = (overrides: Partial<RootObservables> = {}): RootObservables => ({
  headers: {},
  setCookies: [],
  urls: ['https://shop.example/'],
  body: '',
  ...overrides,
});

test('explicit PHP server header is strong evidence and likely status', () => {
  const result = detectPhp(input({ headers: { 'x-powered-by': 'PHP/8.2.14' } }));
  assert.equal(result.status, 'likely');
  assert.equal(result.phpVersion, '8.2.14');
  assert.deepEqual(result.evidence[0], {
    indicator: 'X-Powered-By PHP disclosure',
    value: 'PHP/8.2.14',
    strength: 'strong',
    source: 'header',
    explanation: 'The response header explicitly names PHP; this is direct technology disclosure.',
  });
  assert.equal(result.assessment.method, 'heuristic');
  assert.equal(result.assessment.calibrated, false);
  assert.ok(!('confidence' in result));
});

test('PHPSESSID is strong heuristic evidence, with a non-definitive explanation', () => {
  const result = detectPhp(input({ setCookies: ['PHPSESSID=secret-value; Path=/; HttpOnly'] }));
  assert.equal(result.status, 'likely');
  assert.equal(result.evidence[0].strength, 'strong');
  assert.equal(result.evidence[0].value, 'PHPSESSID');
  assert.match(result.evidence[0].explanation, /not definitive proof/i);
  assert.ok(!JSON.stringify(result).includes('secret-value'));
});

test('a single PHP endpoint is supporting evidence only', () => {
  const result = detectPhp(input({ urls: ['https://shop.example/index.php?token=should-not-leak'] }));
  assert.equal(result.status, 'inconclusive');
  assert.equal(result.evidence.length, 1);
  assert.equal(result.evidence[0].strength, 'medium');
  assert.ok(!JSON.stringify(result).includes('should-not-leak'));
});

test('independent endpoint and framework indicators support likely status', () => {
  const result = detectPhp(input({
    urls: ['https://shop.example/index.php'],
    body: '<meta name="generator" content="WordPress 6.5">',
  }));
  assert.equal(result.status, 'likely');
  assert.deepEqual(result.frameworks, ['WordPress']);
  assert.match(result.assessment.explanation, /independent supporting indicator class/i);
});

test('no indicators produce not_detected', () => {
  const result = detectPhp(input());
  assert.equal(result.status, 'not_detected');
  assert.deepEqual(result.evidence, []);
  assert.equal(result.assessment.calibrated, false);
});

test('weak generic token evidence remains inconclusive', () => {
  const result = detectPhp(input({ setCookies: ['XSRF-TOKEN=abc123; Path=/'] }));
  assert.equal(result.status, 'inconclusive');
  assert.equal(result.evidence[0].strength, 'weak');
});

test('duplicate endpoint observations do not increase the classification', () => {
  const result = detectPhp(input({ urls: [
    'https://shop.example/index.php?first=1',
    'https://shop.example/index.php?second=2',
    'https://shop.example/index.php?first=1',
  ] }));
  assert.equal(result.status, 'inconclusive');
  assert.equal(result.evidence.filter((item) => item.indicator === '.php endpoint').length, 1);
  assert.ok(!JSON.stringify(result).includes('first=1'));
});

test('missing and malformed observations safely return no evidence', () => {
  for (const malformed of [null, undefined, {}, {
    headers: null,
    setCookies: [null, 3],
    urls: [null, 3],
    body: { html: true },
  }]) {
    const result = detectPhp(malformed as RootObservables | null | undefined);
    assert.equal(result.status, 'not_detected');
    assert.deepEqual(result.evidence, []);
    assert.equal(result.assessment.method, 'heuristic');
  }
});
