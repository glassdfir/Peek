// Unit tests. Run with: npm test   (node --test)
// Reference values were cross-checked against pefile 2024.x.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parsePE, parseVersionInfo, peChecksum, imphash, toJSON } from '../src/pe.js';
import { md5, sha1, sha256, entropy } from '../src/hash.js';
import { analyze, guessCompiler } from '../src/analyze.js';

const corpus = (name) => new Uint8Array(readFileSync(new URL(`./corpus/${name}`, import.meta.url)));
const enc = (s) => new TextEncoder().encode(s);

test('hashes match reference vectors', () => {
  assert.equal(md5(enc('')), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5(enc('The quick brown fox jumps over the lazy dog')), '9e107d9d372bb6826bd81d3542a419d6');
  assert.equal(sha1(enc('abc')), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(sha256(enc('abc')), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256(enc('a'.repeat(1000))), '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3');
  // padding boundaries
  assert.equal(md5(enc('x'.repeat(55))), '04364420e25c512fd958a70738aa8f72');
  assert.equal(md5(enc('x'.repeat(56))), '668a72d5ba17f08e62dabcafad6db14b');
  assert.equal(md5(enc('x'.repeat(64))), 'c1bb4f81d892b2d57947682aeb252456');
  assert.equal(entropy(new Uint8Array(256).map((_, i) => i)), 8);
  assert.equal(entropy(new Uint8Array(100)), 0);
});

test('parses a 32-bit MSVC executable (t32.exe)', () => {
  const pe = parsePE(corpus('t32.exe'));
  assert.deepEqual(pe.errors, []);
  assert.deepEqual(pe.warnings, []);
  assert.equal(pe.kind, 'Executable');
  assert.equal(pe.fileHeader.machineName, 'x86 (i386)');
  assert.equal(pe.optionalHeader.format, 'PE32');
  assert.equal(pe.fileHeader.timestamp, '2022-08-06T06:41:06Z');
  assert.deepEqual(pe.sections.map((s) => s.name), ['.text', '.rdata', '.data', '.rsrc', '.reloc']);
  assert.equal(pe.sections[0].md5, '080025b5f343f1e0aa6a9095a2df3d75');
  assert.equal(pe.sections[0].entropy.toFixed(2), '6.46');
  assert.equal(pe.entryPoint.section, '.text');
  assert.equal(pe.entryPoint.offset, 12265);
  assert.deepEqual(pe.imports.map((d) => [d.name, d.entries.length]), [['KERNEL32.dll', 82], ['SHLWAPI.dll', 3]]);
  assert.ok(pe.imports[0].entries.some((e) => e.name === 'GetProcAddress'));
  assert.equal(pe.exports, null);
  assert.equal(pe.resources.count, 10);
  assert.deepEqual(pe.resources.types.map((t) => t.typeName), ['ICON', 'GROUP_ICON', 'VERSION', 'MANIFEST']);
  assert.equal(pe.resources.versionInfo.fixed.fileVersion, '1.1.0.14');
  assert.equal(pe.resources.versionInfo.strings.OriginalFilename, 't32.exe');
  assert.equal(pe.resources.versionInfo.strings.CompanyName, 'Simple Launcher User');
  assert.deepEqual(pe.resources.versionInfo.translations, [{ lang: 1033, codePage: 1200 }]);
  assert.match(pe.resources.manifest, /requestedExecutionLevel/);
  assert.equal(pe.debug[0].codeView.pdb, 'C:\\Users\\Vinay\\Projects\\simple_launcher\\dist\\t32.pdb');
  assert.equal(pe.debug[0].codeView.guid, '085923a1-b7ab-44ed-b16b-45e583405715');
  assert.deepEqual(pe.relocations, { blocks: 18, entries: 1172, size: 2488 });
  assert.equal(pe.rich.valid, true);
  assert.equal(pe.rich.entries.length, 9);
  assert.equal(pe.hashes.md5, '07894acc08732f8b6adade78d3038376');
  assert.equal(pe.hashes.sha1, 'c6f8034e2e8183d35d3f2b035405294ee01fa273');
  assert.equal(pe.hashes.sha256, '6b4195e640a85ac32eb6f9628822a622057df1e459df7c17a12f97aeabc9415b');
  assert.equal(pe.hashes.imphash, '5e24f42b46c247f13d78f0f21a4a2bf7');
  assert.equal(pe.hashes.richHash, 'e666c418128c31da81514c8aa0b1bb8b');
  assert.deepEqual(pe.checksum, { stored: 0x1a332, computed: 0x1a332, matches: true });
  assert.equal(pe.overlay, null);
  assert.equal(pe.certificates, null);
  assert.equal(guessCompiler(pe), 'MSVC (VS 2010)');
  JSON.stringify(toJSON(pe)); // must be serialisable
});

test('parses a 64-bit executable (w64.exe) and an ARM64 one (t64-arm.exe)', () => {
  const w = parsePE(corpus('w64.exe'));
  assert.equal(w.optionalHeader.format, 'PE32+');
  assert.equal(w.optionalHeader.subsystemName, 'Windows GUI');
  assert.equal(w.optionalHeader.imageBase, 0x140000000);
  assert.deepEqual(w.imports.map((d) => [d.name, d.entries.length]), [['KERNEL32.dll', 85], ['USER32.dll', 6], ['SHLWAPI.dll', 3]]);
  assert.equal(w.hashes.imphash, 'ad2258898f0fbdcaaa6098836dd9129f');
  assert.equal(w.hashes.richHash, '1a442f38c598620039bf2ec73ac0964b');
  assert.equal(w.exceptions.count > 0, true);
  assert.equal(w.checksum.matches, true);

  const a = parsePE(corpus('t64-arm.exe'));
  assert.equal(a.fileHeader.machineName, 'ARM64');
  assert.equal(a.hashes.imphash, '613f4d6c7804cf374b32622f85303b42');
  assert.equal(a.hashes.richHash, '55bcb9d56fc3d12df74e9048ca2d0def');
  assert.deepEqual(a.loadConfig.guardFlagNames, ['CF_INSTRUMENTED']);
  assert.equal(a.checksum.stored, 0);
  assert.equal(a.checksum.computed, 0x2dfec);
  assert.deepEqual(a.debug.map((d) => d.typeName), ['CodeView', 'VC feature', 'POGO']);
});

test('analysis of a clean build produces no high findings', () => {
  const pe = parsePE(corpus('t32.exe'));
  const a = analyze(pe, { fileName: 't32.exe' });
  assert.equal(a.counts.high, 0);
  assert.equal(a.counts.medium, 0);
  assert.ok(a.notableImports.some((g) => g.group === 'Dynamic API resolution'));
  assert.equal(a.summary.compiler, 'MSVC (VS 2010)');
  assert.equal(a.summary.originalFilename, 't32.exe');
  const renamed = analyze(pe, { fileName: 'svchost.exe' });
  assert.ok(renamed.findings.some((f) => f.title === 'OriginalFilename differs from file name'));
});

test('tolerates damage: truncation, bad e_lfanew, bogus section count, EP outside sections', () => {
  const base = corpus('t32.exe');
  // not a PE at all
  assert.deepEqual(parsePE(enc('hello world, definitely not a PE')).errors, ['No MZ signature: not a DOS/PE file.']);
  // e_lfanew past EOF
  const bad = base.slice();
  new DataView(bad.buffer).setUint32(0x3c, 0x7fffffff, true);
  assert.match(parsePE(bad).errors[0], /No PE signature/);
  // truncated to the middle of the section data: headers parse, sections flagged, directories degrade
  const cut = base.slice(0, 0x3000);
  const pe = parsePE(cut);
  assert.deepEqual(pe.errors, []);
  assert.equal(pe.sections.length, 5);
  assert.ok(pe.sections.some((s) => s.truncated));
  assert.ok(pe.warnings.length > 0, 'directory parse failures are reported as warnings');
  const a = analyze(pe, { now: Date.parse('2026-01-01') });
  assert.ok(a.findings.some((f) => /truncated/.test(f.title)));
  // section count of 500: capped, warned, still parses
  const many = base.slice();
  new DataView(many.buffer).setUint16(new DataView(many.buffer).getUint32(0x3c, true) + 6, 500, true);
  const pm = parsePE(many);
  assert.ok(pm.warnings.some((w) => /NumberOfSections is 500/.test(w.text)));
  // entry point in no section + zero timestamp + W+X .text
  const evil = base.slice();
  const dv = new DataView(evil.buffer);
  const nt = dv.getUint32(0x3c, true);
  dv.setUint32(nt + 4 + 4, 0, true); // TimeDateStamp
  dv.setUint32(nt + 24 + 16, 0x7f0000, true); // AddressOfEntryPoint
  const sec0 = nt + 24 + dv.getUint16(nt + 4 + 16, true);
  dv.setUint32(sec0 + 36, dv.getUint32(sec0 + 36, true) | 0x80000000, true); // .text += MEM_WRITE
  const ae = analyze(parsePE(evil), { fileName: 't32.exe' });
  const titles = ae.findings.map((f) => f.title);
  assert.ok(titles.includes('Entry point is outside every section'));
  assert.ok(titles.includes('Compile timestamp is zero'));
  assert.ok(titles.includes('Section .text is writable and executable'));
  assert.ok(ae.counts.high >= 2);
});

test('packer-style section names and future timestamps are flagged', () => {
  const b = corpus('w64.exe').slice();
  const dv = new DataView(b.buffer);
  const nt = dv.getUint32(0x3c, true);
  dv.setUint32(nt + 8, 0xffffff00, true); // far-future timestamp
  const sec0 = nt + 24 + dv.getUint16(nt + 20, true);
  b.set(enc('UPX1\0\0\0\0'), sec0);
  const a = analyze(parsePE(b), { now: Date.parse('2026-01-01') });
  assert.ok(a.findings.some((f) => f.title === 'Packer section name: UPX1'));
  assert.equal(a.packerHint, 'UPX');
  assert.ok(a.findings.some((f) => f.title === 'Compile timestamp is in the future'));
});

test('imphash follows pefile rules (lowercase, extension stripped, ordinals via ws2_32 table)', () => {
  const h = imphash([
    { name: 'KERNEL32.DLL', entries: [{ name: 'CreateFileA', byOrdinal: false }, { name: 'ExitProcess', byOrdinal: false }] },
    { name: 'ws2_32.dll', entries: [{ byOrdinal: true, ordinal: 23 }, { byOrdinal: true, ordinal: 999 }] },
    { name: 'custom.bin', entries: [{ name: 'Fn', byOrdinal: false }] },
  ]);
  assert.equal(h, md5(enc('kernel32.createfilea,kernel32.exitprocess,ws2_32.socket,ws2_32.ord999,custom.bin.fn')));
  assert.equal(imphash([]), null);
});

test('PE checksum algorithm', () => {
  const b = corpus('w64.exe');
  const nt = new DataView(b.buffer).getUint32(0x3c, true);
  assert.equal(peChecksum(b, nt + 24 + 64), 0x1d1a2);
  // changing one byte outside the checksum field changes the result
  const c = b.slice(); c[0x400] ^= 1;
  assert.notEqual(peChecksum(c, nt + 24 + 64), 0x1d1a2);
});

test('version info parser handles a hand-built block', () => {
  // VS_VERSIONINFO with StringFileInfo/040904b0/ProductName = "Peek"
  const u16 = (s) => [...s].flatMap((c) => [c.charCodeAt(0), 0]).concat([0, 0]);
  const pad = (a) => { while (a.length % 4) a.push(0); return a; };
  const block = (key, valueBytes, children, type = 0, valueLen = valueBytes.length) => {
    const body = pad([0, 0, 0, 0, 0, 0, ...u16(key)]);
    const all = pad([...body, ...valueBytes]).concat(children);
    all[0] = all.length & 0xff; all[1] = all.length >> 8; all[2] = valueLen & 0xff; all[3] = valueLen >> 8; all[4] = type;
    return all;
  };
  const str = block('ProductName', pad(u16('Peek')), [], 1, 5);
  const table = block('040904b0', [], str);
  const sfi = block('StringFileInfo', [], table);
  const fixed = new Array(52).fill(0); fixed[0] = 0xbd; fixed[1] = 0x04; fixed[2] = 0xef; fixed[3] = 0xfe; fixed[10] = 2; fixed[14] = 3; // 2.0.3.0
  const root = block('VS_VERSION_INFO', fixed, sfi, 0, 52);
  const v = parseVersionInfo(new Uint8Array(root));
  assert.equal(v.strings.ProductName, 'Peek');
  assert.equal(v.fixed.fileVersion, '2.0.3.0');
});
