// Password-protected ZIP support. Archives are generated here (test/zipfixture.mjs);
// the "sample" inside them is the harmless t32.exe launcher from the corpus.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateRawSync } from 'node:zlib';
import { createCipheriv, randomBytes } from 'node:crypto';
import { makeZip } from './zipfixture.mjs';
import { isZip, readZip, extractEntry, findPassword, classifyEntries, inflateRaw, crc32, sniffKind, safeName, aesExpandKey, aesEncryptBlock, ZipError, MAX_EXTRACT } from '../src/zip.js';
import { parsePE } from '../src/pe.js';
import { sha256 } from '../src/hash.js';
import { caseItems } from '../src/suite.js';
import { analyze } from '../src/analyze.js';

const exe = new Uint8Array(readFileSync(new URL('./corpus/t32.exe', import.meta.url)));
const dll = new Uint8Array(readFileSync(new URL('./corpus/wheels/markupsafe_speedups.pyd', import.meta.url)));
const text = new TextEncoder().encode('Password: infected\nDo not run.\n'.repeat(20));
const code = (c) => (e) => e instanceof ZipError && e.code === c;

function openOnly(zip, password) {
  const { entries } = readZip(zip);
  const pw = password ?? findPassword(zip, entries);
  return { entries, pw, out: extractEntry(zip, entries.find((e) => !e.dir), { password: pw }) };
}

test('ZipCrypto zip with "infected" yields the inner EXE byte for byte', () => {
  for (const method of ['deflate', 'store']) {
    const zip = makeZip([{ name: 'sample.exe', data: exe, encryption: 'zipcrypto', method }]);
    assert.ok(isZip(zip));
    const { entries, pw, out } = openOnly(zip);
    assert.equal(pw, 'infected');
    assert.equal(entries[0].encryption, 'ZipCrypto');
    assert.equal(sha256(out), sha256(exe));
    assert.equal(parsePE(out).kind, 'Executable');
  }
});

test('AES-256 (AE-2 and AE-1) and AES-128 zips decrypt', () => {
  for (const [aesVersion, strength, label] of [[2, 3, 'AES-256'], [1, 3, 'AES-256'], [2, 1, 'AES-128']]) {
    const zip = makeZip([{ name: 'a/b/sample.exe', data: exe, encryption: 'aes', aesVersion, strength }]);
    const { entries, pw, out } = openOnly(zip);
    assert.equal(entries[0].encryption, label);
    assert.equal(entries[0].methodName, 'deflate');
    assert.equal(pw, 'infected');
    assert.equal(sha256(out), sha256(exe));
  }
});

test('AES block cipher matches node:crypto for 128/192/256-bit keys', () => {
  for (const n of [16, 24, 32]) {
    const key = randomBytes(n), block = randomBytes(16), got = new Uint8Array(16);
    aesEncryptBlock(aesExpandKey(key), block, got);
    const c = createCipheriv(`aes-${n * 8}-ecb`, key, null); c.setAutoPadding(false);
    assert.deepEqual(Buffer.from(got), c.update(block));
  }
});

test('wrong password: not guessed, then rejected with bad-password for both ciphers', () => {
  for (const encryption of ['zipcrypto', 'aes']) {
    const zip = makeZip([{ name: 'x.exe', data: exe, encryption, password: 'hunter2' }]);
    const { entries } = readZip(zip);
    assert.equal(findPassword(zip, entries), null);
    assert.throws(() => extractEntry(zip, entries[0], {}), code('need-password'));
    // ZipCrypto's 1-byte check passes ~1/256 wrong passwords; try many so that path is hit too.
    for (let i = 0; i < 600; i++) assert.throws(() => extractEntry(zip, entries[0], { password: 'guess' + i }), code('bad-password'));
    assert.equal(sha256(extractEntry(zip, entries[0], { password: 'hunter2' })), sha256(exe));
  }
});

test('several entries: every PE is found, folders skipped, the chosen one extracts', () => {
  const zip = makeZip([
    { name: 'readme.txt', data: text, encryption: 'zipcrypto' },
    { name: 'bin/', data: new Uint8Array(0), method: 'store' },
    { name: 'bin/dropper.exe', data: exe, encryption: 'zipcrypto' },
    { name: 'bin/payload.dll', data: dll, encryption: 'zipcrypto', method: 'store' },
  ]);
  const { entries } = readZip(zip);
  assert.equal(entries.length, 4);
  assert.ok(entries[1].dir);
  const pw = findPassword(zip, entries);
  const kinds = classifyEntries(zip, entries, pw);
  assert.deepEqual(kinds.map((k) => [k.entry.name, k.kind]), [['readme.txt', 'other'], ['bin/dropper.exe', 'pe'], ['bin/payload.dll', 'pe']]);
  assert.equal(sha256(extractEntry(zip, entries[3], { password: pw })), sha256(dll));
});

test('a non-PE entry is classified as other and still extracts', () => {
  const zip = makeZip([{ name: 'notes.txt', data: text, encryption: 'zipcrypto' }]);
  const { entries } = readZip(zip);
  const [k] = classifyEntries(zip, entries, 'infected');
  assert.equal(k.kind, 'other');
  assert.deepEqual(extractEntry(zip, entries[0], { password: 'infected' }), text);
  assert.equal(sniffKind(new Uint8Array([0x4d, 0x5a])), 'mz');
  assert.equal(sniffKind(exe.subarray(0, 4096)), 'pe');
});

test('unencrypted zips open with no password', () => {
  const zip = makeZip([{ name: 'plain.exe', data: exe }]);
  const { entries, pw, out } = openOnly(zip);
  assert.equal(pw, '');
  assert.equal(entries[0].encrypted, false);
  assert.equal(sha256(out), sha256(exe));
});

test('truncated zips give a clear truncated/corrupt error, never a crash', () => {
  const zip = makeZip([{ name: 'sample.exe', data: exe, encryption: 'zipcrypto' }]);
  // Cut off the central directory: the classic broken download.
  assert.throws(() => readZip(zip.subarray(0, zip.length - 40)), (e) => e instanceof ZipError && ['truncated', 'corrupt'].includes(e.code) && /truncated|damaged/i.test(e.message));
  assert.throws(() => readZip(zip.subarray(0, 4000)), code('truncated'));
  // Every prefix length either throws a ZipError or (when it still parses) extraction does.
  for (let n = 0; n < zip.length; n += 97) {
    try { const { entries } = readZip(zip.subarray(0, n)); extractEntry(zip.subarray(0, n), entries[0], { password: 'infected' }); assert.fail('truncated zip extracted'); }
    catch (e) { assert.ok(e instanceof ZipError, `prefix ${n}: ${e && e.stack}`); }
  }
  assert.throws(() => readZip(exe), code('not-zip'));
});

test('corrupt data: CRC mismatch, damaged deflate and AES tamper are reported', () => {
  const plain = makeZip([{ name: 'a.exe', data: exe, crc: 0x12345678 }]);
  assert.throws(() => extractEntry(plain, readZip(plain).entries[0], {}), code('crc'));

  const zip = makeZip([{ name: 'a.exe', data: exe }]);
  const bad = zip.slice(); bad[200] ^= 0xff; bad[201] ^= 0x55;
  assert.throws(() => extractEntry(bad, readZip(bad).entries[0], {}), (e) => e instanceof ZipError && ['crc', 'corrupt', 'truncated'].includes(e.code));

  const aes = makeZip([{ name: 'a.exe', data: exe, encryption: 'aes' }]);
  const tampered = aes.slice(); tampered[300] ^= 1;
  assert.throws(() => extractEntry(tampered, readZip(tampered).entries[0], { password: 'infected' }), code('crc'));
});

test('zip bombs stop at the cap or at the declared size', () => {
  // Honest header over the limit: refused before any work.
  const big = makeZip([{ name: 'bomb.exe', data: new Uint8Array(1 << 20) }]);
  assert.throws(() => extractEntry(big, readZip(big).entries[0], { maxSize: 1 << 16 }), code('too-big'));
  // Lying header: says 4 KB, inflates to 1 MiB. Stops at 4 KB.
  const liar = makeZip([{ name: 'bomb.exe', data: new Uint8Array(1 << 20), size: 4096 }]);
  assert.throws(() => extractEntry(liar, readZip(liar).entries[0], {}), code('too-big'));
  const huge = makeZip([{ name: 'bomb.exe', data: new Uint8Array(16), size: MAX_EXTRACT + 1 }]);
  assert.throws(() => extractEntry(huge, readZip(huge).entries[0], {}), code('too-big'));
});

test('inflateRaw agrees with zlib and survives random garbage', () => {
  const rnd = randomBytes(5000);
  for (const data of [exe, dll, text, new Uint8Array(0), rnd, new Uint8Array(70000).fill(7)]) {
    for (const level of [0, 1, 9]) assert.deepEqual(inflateRaw(deflateRawSync(data, { level })), new Uint8Array(data));
  }
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
  let seed = 7;
  const next = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0);
  const base = deflateRawSync(exe);
  const t0 = Date.now();
  for (let i = 0; i < 400; i++) {
    const m = Buffer.from(base);
    for (let k = 0; k < 1 + (next() % 8); k++) m[next() % m.length] ^= 1 << (next() % 8);
    try { inflateRaw(m.subarray(0, next() % m.length + 1), { maxOut: 1 << 20 }); }
    catch (e) { assert.ok(e instanceof ZipError, e && e.stack); }
  }
  assert.ok(Date.now() - t0 < 20000, 'inflate fuzz took too long');
});

test('readZip survives mutated archives without throwing anything but ZipError', () => {
  const zip = makeZip([{ name: 'a.exe', data: exe, encryption: 'zipcrypto' }, { name: 'b.txt', data: text, encryption: 'aes' }]);
  let seed = 99;
  const next = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0);
  for (let i = 0; i < 500; i++) {
    const m = zip.slice();
    // Bias mutations toward the directory and headers, where the pointers live.
    for (let k = 0; k < 1 + (next() % 6); k++) { const at = next() % 3 ? m.length - 1 - (next() % 200) : next() % m.length; m[at] = next() & 0xff; }
    try { const { entries } = readZip(m); for (const e of entries) { try { extractEntry(m, e, { password: 'infected', maxSize: 1 << 20 }); } catch (err) { if (!(err instanceof ZipError)) throw err; } } }
    catch (e) { assert.ok(e instanceof ZipError, `seed ${i}: ${e && e.stack}`); }
  }
});

test('names: bidi overrides and control characters are shown escaped', () => {
  assert.equal(safeName('invoice‮exe.pdf'), 'invoice\\u{202e}exe.pdf');
  const zip = makeZip([{ name: 'evil‮txt.exe', data: exe }]);
  assert.equal(readZip(zip).entries[0].displayName, 'evil\\u{202e}txt.exe');
});

test('Add to case records the archive as the evidence source', () => {
  const pe = parsePE(exe);
  const items = caseItems({ name: 'sample.exe', size: exe.length, pe, analysis: analyze(pe, { fileName: 'sample.exe' }), origin: { archive: 'abc.zip', path: 'x/sample.exe', encryption: 'ZipCrypto' } });
  assert.equal(items.evidence[0].sha256, sha256(exe));
  assert.match(items.evidence[0].source, /abc\.zip/);
  assert.match(items.evidence[0].note, /Extracted from abc\.zip/);
});

// Cross-check against a real archiver where one is installed (Info-ZIP `zip` ships with macOS).
test('opens a ZipCrypto archive made by Info-ZIP zip -P infected', (t) => {
  try { execFileSync('zip', ['-v'], { stdio: 'ignore' }); } catch { return t.skip('zip not installed'); }
  const dir = mkdtempSync(join(tmpdir(), 'peek-zip-'));
  try {
    writeFileSync(join(dir, 'sample.exe'), exe);
    writeFileSync(join(dir, 'notes.txt'), text);
    execFileSync('zip', ['-q', '-P', 'infected', 'out.zip', 'sample.exe', 'notes.txt'], { cwd: dir });
    const zip = new Uint8Array(readFileSync(join(dir, 'out.zip')));
    const { entries } = readZip(zip);
    const pw = findPassword(zip, entries);
    assert.equal(pw, 'infected');
    assert.equal(sha256(extractEntry(zip, entries.find((e) => e.name === 'sample.exe'), { password: pw })), sha256(exe));
    // Streamed input sets the data-descriptor flag, so the check byte comes from the time field.
    const piped = execFileSync('zip', ['-q', '-P', 'infected', '-', '-'], { input: Buffer.from(exe) });
    const z2 = new Uint8Array(piped), e2 = readZip(z2).entries;
    assert.equal(sha256(extractEntry(z2, e2[0], { password: findPassword(z2, e2) })), sha256(exe));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
