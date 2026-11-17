// Case 01's implant, as Peek generates it for ?sample=kestrel, must be byte-for-byte the file
// whose SHA-256 and size the case's logs carry (and that Hexes generates).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildKestrel } from '../src/kestrel.js';
import { parsePE } from '../src/pe.js';
import { analyze } from '../src/analyze.js';

test('Kestrel implant matches the hash pinned by Case 01', () => {
  const pe = parsePE(buildKestrel());
  assert.equal(pe.fileSize, 117252);
  assert.equal(pe.hashes.sha256, '14b5a9523b3412a001857c3b2d6f668320032ab5511074fc44d2057d2ddb40c5');
  assert.equal(pe.fileHeader.timestamp, '2026-10-09T22:14:05Z');
});

test('Peek sees the implant for what it is: a header shell with everything in the overlay', () => {
  const a = analyze(parsePE(buildKestrel()), { fileName: 'update.exe' });
  const titles = a.findings.filter((f) => f.severity === 'high').map((f) => f.title);
  assert.ok(titles.includes('Every section is empty'));
  assert.ok(titles.includes('No import table'));
  assert.ok(titles.includes('Overlay is 100% of the file'));
});
