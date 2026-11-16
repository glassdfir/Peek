// Mutation fuzzer for the parser. Takes the corpus files, damages them in the
// ways malware authors and broken downloads do, and asserts that parsePE,
// analyze and toJSON never throw and never take absurdly long.
//
//   node test/fuzz.mjs                 # 2000 iterations per corpus file
//   node test/fuzz.mjs 20000           # longer run
//   node test/fuzz.mjs 2000 12345      # fixed seed, for reproducing
//   FUZZ_SAVE=1 node test/fuzz.mjs     # write failing inputs to test/fuzz-failures/
//
// Also exported as fuzzOnce() so the unit tests can run a short pass.
import { readFileSync, readdirSync, writeFileSync, mkdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parsePE, toJSON } from '../src/pe.js';
import { analyze } from '../src/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));

// mulberry32: small seeded PRNG so failures are reproducible
export function rng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
const INTERESTING32 = [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x200, 0x1000, 0x7fff, 0x8000, 0xffff, 0x10000, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff];

// Produce one damaged copy. Header bytes get most of the attention because
// that is where structure lives; a few mutations hit the body and the tail.
export function mutate(src, r) {
  let b = src.slice();
  const dv = () => new DataView(b.buffer, b.byteOffset, b.byteLength);
  const headerEnd = Math.min(b.length, 0x600);
  const nOps = 1 + Math.floor(r() * 4);
  const ops = [];
  for (let i = 0; i < nOps; i++) {
    const op = pick(r, ['flip', 'flip', 'dword', 'dword', 'dword', 'word', 'truncate', 'zero', 'fill', 'swap', 'grow', 'rva']);
    ops.push(op);
    const inHeader = r() < 0.8;
    const at = Math.floor(r() * (inHeader ? headerEnd : b.length));
    switch (op) {
      case 'flip': { const n = 1 + Math.floor(r() * 8); for (let k = 0; k < n; k++) { const o = Math.floor(r() * (inHeader ? headerEnd : b.length)); b[o] ^= 1 << Math.floor(r() * 8); } break; }
      case 'dword': if (at + 4 <= b.length) dv().setUint32(at & ~3, r() < 0.7 ? pick(r, INTERESTING32) : Math.floor(r() * 0x100000000), true); break;
      case 'word': if (at + 2 <= b.length) dv().setUint16(at & ~1, r() < 0.7 ? pick(r, [0, 1, 0xff, 0x100, 0x7fff, 0x8000, 0xffff]) : Math.floor(r() * 0x10000), true); break;
      case 'truncate': b = b.slice(0, Math.max(1, Math.floor(r() * (r() < 0.5 ? headerEnd : b.length)))); break;
      case 'zero': { const len = 1 + Math.floor(r() * 64); b.fill(0, at, Math.min(b.length, at + len)); break; }
      case 'fill': { const len = 1 + Math.floor(r() * 64); b.fill(pick(r, [0xff, 0x80, 0x41]), at, Math.min(b.length, at + len)); break; }
      case 'swap': { let len = 8 + Math.floor(r() * 64); const a2 = Math.floor(r() * b.length); len = Math.min(len, b.length - at, b.length - a2); if (len <= 0) break; const tmp = b.slice(at, at + len); b.set(b.slice(a2, a2 + len), at); b.set(tmp, a2); break; }
      case 'grow': { const extra = new Uint8Array(Math.floor(r() * 4096)); for (let k = 0; k < extra.length; k++) extra[k] = Math.floor(r() * 256); const nb = new Uint8Array(b.length + extra.length); nb.set(b); nb.set(extra, b.length); b = nb; break; }
      case 'rva': { // point a random dword in the headers at a random place in or beyond the file
        if (at + 4 <= b.length) dv().setUint32(at & ~3, Math.floor(r() * b.length * (r() < 0.3 ? 4 : 1)), true); break; }
    }
  }
  return { bytes: b, ops };
}

export function fuzzOnce(src, seed, opts = {}) {
  const r = rng(seed);
  const { bytes, ops } = mutate(src, r);
  const t0 = Date.now();
  try {
    const pe = parsePE(bytes, { fileHashes: false });
    const a = analyze(pe, { fileName: 'fuzz.exe', now: Date.parse('2026-01-01') });
    JSON.stringify(toJSON(pe));
    JSON.stringify(a);
    const ms = Date.now() - t0;
    if (ms > (opts.budgetMs || 1500)) return { ok: false, seed, ops, error: `took ${ms}ms`, bytes };
    return { ok: true, seed, ops, ms };
  } catch (e) {
    return { ok: false, seed, ops, error: e && e.stack || String(e), bytes };
  }
}

export function corpusFiles() {
  const dir = join(here, 'corpus');
  return readdirSync(dir).filter((f) => !f.startsWith('.') && !f.endsWith('.md') && statSync(join(dir, f)).isFile()).map((f) => ({ name: f, bytes: new Uint8Array(readFileSync(join(dir, f))) }));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const iters = Number(process.argv[2] || 2000);
  const baseSeed = process.argv[3] !== undefined ? Number(process.argv[3]) : (Date.now() & 0xffffff);
  const files = corpusFiles();
  let failures = 0, slowest = 0, total = 0;
  const t0 = Date.now();
  for (const f of files) {
    for (let i = 0; i < iters; i++) {
      const seed = (baseSeed + i * 7919 + f.name.length) >>> 0;
      const res = fuzzOnce(f.bytes, seed);
      total++;
      if (res.ok) { if (res.ms > 250) console.log(`SLOW ${f.name} seed=${seed} ${res.ms}ms ops=${res.ops.join(',')}`); slowest = Math.max(slowest, res.ms); continue; }
      failures++;
      console.log(`FAIL ${f.name} seed=${seed} ops=${res.ops.join(',')}\n  ${res.error.split('\n').slice(0, 3).join('\n  ')}`);
      if (process.env.FUZZ_SAVE) { mkdirSync(join(here, 'fuzz-failures'), { recursive: true }); writeFileSync(join(here, 'fuzz-failures', `${f.name}.${seed}.bin`), res.bytes); }
      if (failures >= 20) break;
    }
  }
  console.log(`${total} runs over ${files.length} files in ${Date.now() - t0}ms, ${failures} failures, slowest ${slowest}ms (base seed ${baseSeed})`);
  process.exit(failures ? 1 : 0);
}
