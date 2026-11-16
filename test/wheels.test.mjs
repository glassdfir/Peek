// Real-world DLLs and a .NET assembly taken from Windows wheels on PyPI (see corpus/NOTICE.md).
// Reference values from pefile 2024.8.26.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parsePE } from '../src/pe.js';
import { analyze } from '../src/analyze.js';

const load = (name) => new Uint8Array(readFileSync(new URL(`./corpus/wheels/${name}`, import.meta.url)));

test('DLL with one export (markupsafe _speedups.pyd)', () => {
  const pe = parsePE(load('markupsafe_speedups.pyd'));
  assert.deepEqual(pe.errors, []);
  assert.equal(pe.kind, 'DLL');
  assert.equal(pe.isDll, true);
  assert.equal(pe.hashes.sha256.slice(0, 16), 'a1bf1fb566f920b5');
  assert.equal(pe.hashes.imphash, '742935dedc475bd9727933e4496eb9ec');
  assert.equal(pe.hashes.richHash, '539bfe39b9e9b1b238fbe017ffbf76e5');
  assert.equal(pe.exports.name, '_speedups.cp312-win_amd64.pyd');
  assert.equal(pe.exports.ordinalBase, 1);
  assert.deepEqual(pe.exports.functions.map((f) => [f.ordinal, f.name, f.section]), [[1, 'PyInit__speedups', '.text']]);
  assert.deepEqual(pe.imports.map((d) => [d.name, d.entries.length]), [['python312.dll', 2], ['KERNEL32.dll', 6], ['VCRUNTIME140.dll', 3], ['api-ms-win-crt-runtime-l1-1-0.dll', 8]]);
  const a = analyze(pe, { fileName: 'markupsafe_speedups.pyd' });
  assert.equal(a.counts.high + a.counts.medium, 0);
  assert.ok(a.findings.some((f) => f.title === 'Export name differs from file name'));
});

test('DLL with hundreds of C++ exports (pywintypes312.dll)', () => {
  const pe = parsePE(load('pywintypes312.dll'));
  assert.deepEqual(pe.errors, []);
  assert.equal(pe.hashes.imphash, 'a890defc7bf5ab209cc58c0224464f2e');
  assert.equal(pe.hashes.richHash, 'bf5f1081e32ed8f72937d5d13a90a4cd');
  assert.equal(pe.exports.name, 'pywintypes312.dll');
  assert.equal(pe.exports.functions.length, 307);
  assert.equal(pe.exports.functions.filter((f) => f.forwarder).length, 0);
  assert.deepEqual(pe.exports.functions.slice(0, 2).map((f) => f.name), ['??0PyACL@@QEAA@HH@Z', '??0PyACL@@QEAA@PEAU_ACL@@@Z']);
  assert.ok(pe.exports.functions.every((f) => f.names.length === 1 && f.section));
  // C++ DLLs export data too: vtables land in .rdata, type objects in .data
  assert.equal(pe.exports.functions.filter((f) => f.section !== '.text').length, 26);
  assert.deepEqual(pe.imports.slice(0, 2).map((d) => [d.name, d.entries.length]), [['ADVAPI32.dll', 46], ['USER32.dll', 1]]);
  assert.ok(pe.imports.some((d) => d.name === 'OLEAUT32.dll' && d.entries.length === 5));
});

test('.NET assembly (Python.Runtime.dll)', () => {
  const pe = parsePE(load('Python.Runtime.dll'));
  assert.deepEqual(pe.errors, []);
  assert.equal(pe.kind, '.NET assembly (DLL)');
  assert.equal(pe.hashes.imphash, 'dae02f32a21e03ce65412f6e56942daa');
  assert.equal(pe.rich, null);
  assert.equal(pe.clr.cb, 72);
  assert.equal(pe.dataDirectories[14].rva, 0x2008);
  assert.match(pe.clr.runtimeVersion, /^v\d/);
  assert.ok(pe.clr.flagNames.includes('ILONLY'));
  assert.deepEqual(pe.imports.map((d) => [d.name, d.entries.map((e) => e.display)]), [['mscoree.dll', ['_CorDllMain']]]);
  assert.equal(pe.checksum.matches, true);
  const a = analyze(pe, { fileName: 'Python.Runtime.dll' });
  assert.ok(a.findings.some((f) => f.title === '.NET assembly'));
  assert.ok(!a.findings.some((f) => f.title === 'No import table'));
  assert.match(a.summary.compiler, /^\.NET/);
});

test('service host EXE (pythonservice.exe)', () => {
  const pe = parsePE(load('pythonservice.exe'));
  assert.equal(pe.hashes.imphash, 'f052d7da3c4f2dac9eb682b85c7c9348');
  assert.equal(pe.hashes.richHash, 'bdfb4c063b8026018be2cfcd420764e7');
  assert.equal(pe.kind, 'Executable');
  assert.equal(pe.exports, null);
  const a = analyze(pe, { fileName: 'pythonservice.exe' });
  assert.ok(a.notableImports.some((g) => g.group === 'Persistence / registry / services'));
});
