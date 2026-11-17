// Case 01's implant, as Peek generates it for ?sample=arclight, must be byte-for-byte the file
// whose SHA-256 and size the case's logs carry (and that Hexes generates).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildArclight } from '../src/arclight.js';
import { parsePE } from '../src/pe.js';
import { analyze } from '../src/analyze.js';

test('Arclight implant matches the hash pinned by Case 01', () => {
  const pe = parsePE(buildArclight());
  assert.equal(pe.fileSize, 117256);
  assert.equal(pe.hashes.sha256, '23b0f1f444ae1f7ea41492cebfe268921b13601af721c29e21fa86f46e20e8ce');
  assert.equal(pe.fileHeader.timestamp, '2026-10-09T22:14:05Z');
});

test('Peek sees the implant for what it is: a header shell with everything in the overlay', () => {
  const a = analyze(parsePE(buildArclight()), { fileName: 'update.exe' });
  const titles = a.findings.filter((f) => f.severity === 'high').map((f) => f.title);
  assert.ok(titles.includes('Every section is empty'));
  assert.ok(titles.includes('No import table'));
  assert.ok(titles.includes('Overlay is 100% of the file'));
});
