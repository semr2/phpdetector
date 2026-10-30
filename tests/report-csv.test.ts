import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildFindingsCsv, csvCell } from '../src/lib/services/csv.ts';

test('csv cells neutralise spreadsheet formulas', () => {
  for (const evil of ['=HYPERLINK("http://x")', '+1+1', '-2+3', '@SUM(A1)']) {
    assert.ok(csvCell(evil).replace(/^"/, '').startsWith("'"), evil);
  }
});

test('csv cells quote commas, quotes and newlines', () => {
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell('line1\nline2'), '"line1\nline2"');
  assert.equal(csvCell(null), '');
  assert.equal(csvCell('plain'), 'plain');
});

test('empty simulated CSV explicitly labels the report as demo metadata', () => {
  const csv = buildFindingsCsv([], {
    simulated: true,
    simulationNotice: 'SIMULATED DEMO DATA — no live website was scanned.',
  });
  assert.match(csv, /^data_origin,record_type,notice,/);
  assert.match(csv, /^SIMULATED DEMO DATA,metadata,SIMULATED DEMO DATA/m);
});
