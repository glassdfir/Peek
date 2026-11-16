// Every corkami proof-of-concept in the corpus must parse without throwing, and the
// ones Windows loads must not be rejected. Reference: https://github.com/corkami/pocs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { parsePE, toJSON } from '../src/pe.js';
import { analyze } from '../src/analyze.js';

const dir = new URL('./corpus/corkami/', import.meta.url);
const load = (name) => new Uint8Array(readFileSync(new URL(name, dir)));

// Files the parser is right to reject (pefile rejects them too).
const EXPECTED_REJECTS = new Set([
  'dosZMXP.exe', // a pure DOS executable with the ZM magic; no PE header at all
  'exe2pe.exe', // a 16-bit NE executable
]);

test('every corkami PoC parses without throwing, and only known non-PEs are rejected', () => {
  const names = readdirSync(dir).filter((f) => !f.startsWith('.'));
  assert.ok(names.length > 150, `corpus looks incomplete: ${names.length} files`);
  const rejected = [], slow = [];
  for (const name of names) {
    const t0 = Date.now();
    const pe = parsePE(load(name), { fileHashes: false });
    const a = analyze(pe, { fileName: name, now: Date.parse('2026-01-01') });
    JSON.stringify(toJSON(pe)); JSON.stringify(a);
    if (pe.errors.length) rejected.push(`${name}: ${pe.errors[0]}`);
    if (Date.now() - t0 > 500) slow.push(name);
  }
  assert.deepEqual(rejected.map((r) => r.split(':')[0]).sort(), [...EXPECTED_REJECTS].sort(), rejected.join('\n'));
  assert.deepEqual(slow, []);
});

test('tiny PEs with overlapping headers are accepted and flagged', () => {
  const pe = parsePE(load('tinyW7.exe'));
  assert.deepEqual(pe.errors, []);
  assert.equal(pe.dos.e_lfanew, 4);
  assert.ok(pe.warnings.some((w) => /overlaps the DOS header/.test(w.text)));
  assert.equal(pe.fileHeader.numberOfSections, 0);
  assert.equal(pe.optionalHeader.addressOfEntryPoint, 0x88);
  const a = analyze(pe, { fileName: 'tinyW7.exe' });
  assert.ok(a.findings.some((f) => f.title === 'Entry point is inside the headers'));
  assert.ok(a.findings.some((f) => f.title === 'No sections'));
});

test('zero SizeOfOptionalHeader still yields an optional header and a section table', () => {
  const pe = parsePE(load('nullSOH-XP.exe'));
  assert.deepEqual(pe.errors, []);
  assert.equal(pe.fileHeader.sizeOfOptionalHeader, 0);
  assert.equal(pe.optionalHeader.magic, 0x10b);
  assert.equal(pe.sections.length, 1);
  assert.ok(pe.warnings.some((w) => /section table overlaps the optional header/.test(w.text)));
});

test('a 61-byte PE that ends inside the optional header is reported, not rejected', () => {
  const pe = parsePE(load('d_tiny.dll'));
  assert.deepEqual(pe.errors, []);
  assert.ok(pe.warnings.some((w) => /ends inside the optional header/.test(w.text)));
});

test('the ZM-magic DOS file and the NE file are rejected with a useful message', () => {
  assert.match(parsePE(load('dosZMXP.exe')).errors[0], /No PE signature/);
  assert.match(parsePE(load('exe2pe.exe')).errors[0], /16-bit NE/);
});
