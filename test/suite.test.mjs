// The Tessera hand-off payload: shape matches what Tessera's importCase expects
// (evidence / indicators / findings), with confidence derived from severity.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parsePE } from '../src/pe.js';
import { analyze } from '../src/analyze.js';
import { caseItems } from '../src/suite.js';

test('caseItems builds evidence, hash indicators and high/medium findings', () => {
  const bytes = new Uint8Array(readFileSync(new URL('./corpus/corkami/tinyW7.exe', import.meta.url)));
  const pe = parsePE(bytes);
  const analysis = analyze(pe, { fileName: 'tinyW7.exe' });
  const items = caseItems({ name: 'tinyW7.exe', size: bytes.length, pe, analysis });
  assert.equal(items.evidence.length, 1);
  assert.equal(items.evidence[0].sha256, pe.hashes.sha256);
  assert.equal(items.evidence[0].size, '252');
  assert.match(items.evidence[0].note, /^Examined in Peek: Executable, x86/);
  assert.deepEqual(items.indicators.map((i) => i.type), ['sha256', 'sha1', 'md5']);
  assert.ok(items.indicators.every((i) => i.note === 'tinyW7.exe' && /^[0-9a-f]+$/.test(i.value)));
  const want = analysis.findings.filter((f) => f.severity === 'high' || f.severity === 'medium').length;
  assert.equal(items.findings.length, want);
  assert.ok(want > 0);
  assert.ok(items.findings.every((f) => ['likely', 'possible'].includes(f.confidence) && f.detail.includes(pe.hashes.sha256)));
  assert.ok(items.findings.some((f) => f.confidence === 'likely' && f.title === 'No sections (tinyW7.exe)'));
  JSON.stringify(items);
});
