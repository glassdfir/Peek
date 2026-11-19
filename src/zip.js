// Read-only ZIP reader for password-protected malware samples (MalwareBazaar,
// VirusTotal, vx-underground: usually ZipCrypto with the password "infected",
// sometimes WinZip AES from 7-Zip). Pure JS so it runs the same in the page,
// the worker, the single-file build opened from disk, Node tests and the CLI:
// no WebCrypto (not available everywhere), no DecompressionStream (no
// 'deflate-raw' before Node 20.12, and its output cannot be capped mid-stream).
//
// The archive is hostile input. Every offset and length is bounds-checked,
// entry counts are capped, output is capped at MAX_EXTRACT and at the size the
// central directory declares (a zip bomb stops there, it does not fill memory),
// and every failure is a ZipError with a code the UI turns into a plain message.
// Nothing here executes or writes the extracted bytes anywhere.
import { sha1Bytes } from './hash.js';

/** Largest file Peek will extract: the same 256 MiB the suite hand-off accepts. */
export const MAX_EXTRACT = 256 << 20;
const MAX_ENTRIES = 4096;
export const DEFAULT_PASSWORDS = ['infected'];

export class ZipError extends Error {
  // code: not-zip | corrupt | truncated | unsupported | need-password | bad-password | crc | too-big
  constructor(code, message) { super(message); this.name = 'ZipError'; this.code = code; }
}
const corrupt = (m) => new ZipError('corrupt', m);
const truncated = (m) => new ZipError('truncated', m);

/** True when the bytes start like a ZIP (local file header, or an empty archive). */
export function isZip(bytes) {
  return bytes.length >= 22 && bytes[0] === 0x50 && bytes[1] === 0x4b &&
    ((bytes[2] === 3 && bytes[3] === 4) || (bytes[2] === 5 && bytes[3] === 6) || (bytes[2] === 7 && bytes[3] === 8 && bytes[4] === 0x50 && bytes[5] === 0x4b));
}

// ---------- CRC-32 ----------
const CRC_TABLE = new Int32Array(256);
for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_TABLE[n] = c; }
export function crc32(bytes) {
  let c = -1;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

// ---------- names ----------
// Names without the UTF-8 flag are CP437 (the DOS code page the format began with).
const CP437_HIGH = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';
function decodeName(b, utf8) {
  if (utf8) return new TextDecoder('utf-8').decode(b);
  let s = '';
  for (const c of b) s += c < 0x80 ? String.fromCharCode(c) : CP437_HIGH[c - 0x80];
  return s;
}
// Control characters and bidi overrides ("invoice‮exe.pdf") are shown escaped so a name cannot disguise itself.
const SNEAKY = /[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩﻿]/g;
export const safeName = (s) => s.replace(SNEAKY, (c) => `\\u{${c.charCodeAt(0).toString(16).padStart(4, '0')}}`);
export const baseName = (path) => path.split(/[\\/]/).filter(Boolean).pop() || path || 'file';

const METHODS = { 0: 'stored', 1: 'shrunk', 6: 'imploded', 8: 'deflate', 9: 'deflate64', 12: 'bzip2', 14: 'LZMA', 19: 'LZ77', 93: 'zstd', 95: 'xz', 96: 'JPEG', 97: 'WavPack', 98: 'PPMd', 99: 'AES' };

// ---------- container ----------
/**
 * Parse the central directory. Returns { entries, comment } where each entry is
 * { index, name, displayName, dir, method, methodName, encrypted, encryption,
 *   size, compressedSize, crc, flags, modTime, localOffset, aes }.
 * Throws ZipError for anything that is not a readable ZIP.
 */
export function readZip(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new ZipError('not-zip', 'Not a byte array.');
  const len = bytes.length;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (len < 22) throw new ZipError('not-zip', 'Too short to be a ZIP.');
  const u16 = (o) => dv.getUint16(o, true), u32 = (o) => dv.getUint32(o, true);
  const u64 = (o) => { const v = u32(o) + u32(o + 4) * 0x100000000; return v; };

  // End of central directory: the last 22 bytes plus up to 64 KiB of comment.
  let eocd = -1;
  for (let o = len - 22; o >= Math.max(0, len - 22 - 0xffff); o--) {
    if (u32(o) !== 0x06054b50) continue;
    if (o + 22 + u16(o + 20) <= len) { eocd = o; break; }
  }
  if (eocd < 0) {
    if (isZip(bytes)) throw truncated('The ZIP is truncated or damaged: its central directory (the index at the end of the file) is missing. Re-download the archive.');
    throw new ZipError('not-zip', 'Not a ZIP archive (no end-of-central-directory record).');
  }
  let count = u16(eocd + 10), cdSize = u32(eocd + 12), cdOffset = u32(eocd + 16);
  const comment = decodeName(bytes.subarray(eocd + 22, Math.min(len, eocd + 22 + u16(eocd + 20))), false);
  if (u16(eocd + 4) !== 0 || u16(eocd + 6) !== 0) throw new ZipError('unsupported', 'Multi-volume (split or spanned) ZIPs are not supported. Join the parts into one archive first.');

  // ZIP64 end of central directory, when the classic fields are saturated.
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc >= 0 && u32(loc) === 0x07064b50) {
      const z = u64(loc + 8);
      if (z + 56 > len || u32(z) !== 0x06064b50) throw corrupt('The ZIP64 end-of-central-directory record is missing or out of range.');
      count = u64(z + 32); cdSize = u64(z + 40); cdOffset = u64(z + 48);
    }
  }
  if (cdOffset + cdSize > len) throw truncated(`The central directory claims ${cdSize} bytes at offset ${cdOffset}, past the end of the ${len}-byte file. The archive is truncated or damaged.`);
  if (count > MAX_ENTRIES) throw new ZipError('unsupported', `The archive lists ${count} entries; Peek reads at most ${MAX_ENTRIES}.`);

  const entries = [];
  let o = cdOffset;
  const cdEnd = cdOffset + cdSize;
  for (let i = 0; i < count; i++) {
    if (o + 46 > cdEnd || u32(o) !== 0x02014b50) throw corrupt(`Central directory entry ${i + 1} of ${count} is damaged (bad signature at offset ${o}).`);
    const flags = u16(o + 8);
    let method = u16(o + 10);
    const modTime = u16(o + 12), crc = u32(o + 16);
    let compressedSize = u32(o + 20), size = u32(o + 24);
    const nameLen = u16(o + 28), extraLen = u16(o + 30), commentLen = u16(o + 32);
    let localOffset = u32(o + 42);
    const next = o + 46 + nameLen + extraLen + commentLen;
    if (next > cdEnd) throw corrupt(`Central directory entry ${i + 1} runs past the end of the directory.`);
    const name = decodeName(bytes.subarray(o + 46, o + 46 + nameLen), (flags & 0x800) !== 0);
    let aes = null;
    for (let e = o + 46 + nameLen, eEnd = e + extraLen; e + 4 <= eEnd;) {
      const id = u16(e), sz = u16(e + 2), d = e + 4;
      if (d + sz > eEnd) break;
      if (id === 0x0001) { // ZIP64 extended information: only the saturated fields are present, in this order
        let p = d;
        if (size === 0xffffffff && p + 8 <= d + sz) { size = u64(p); p += 8; }
        if (compressedSize === 0xffffffff && p + 8 <= d + sz) { compressedSize = u64(p); p += 8; }
        if (localOffset === 0xffffffff && p + 8 <= d + sz) { localOffset = u64(p); p += 8; }
      } else if (id === 0x9901 && sz >= 7) { // WinZip AES
        aes = { version: u16(d), strength: bytes[d + 4], method: u16(d + 5) };
      }
      e = d + sz;
    }
    const encrypted = (flags & 1) !== 0;
    let encryption = encrypted ? 'ZipCrypto' : 'none';
    if (method === 99) {
      if (!aes) throw corrupt(`${safeName(name)} is marked AES-encrypted but has no AES extra field.`);
      encryption = `AES-${[0, 128, 192, 256][aes.strength] || '?'}`;
      method = aes.method;
    } else if (encrypted && (flags & 0x40)) encryption = 'PKWARE strong encryption';
    entries.push({
      index: i, name, displayName: safeName(name), dir: name.endsWith('/') || name.endsWith('\\'),
      method, methodName: METHODS[method] || `method ${method}`, encrypted, encryption,
      size, compressedSize, crc, flags, modTime, localOffset, aes,
    });
    o = next;
  }
  return { entries, comment };
}

// Locate an entry's (still compressed, still encrypted) data via its local header.
function entryData(bytes, entry) {
  const o = entry.localOffset;
  if (o + 30 > bytes.length) throw truncated(`${entry.displayName}: its data starts past the end of the file. The archive is truncated.`);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (dv.getUint32(o, true) !== 0x04034b50) throw corrupt(`${entry.displayName}: bad local header at offset ${o}.`);
  const start = o + 30 + dv.getUint16(o + 26, true) + dv.getUint16(o + 28, true);
  const end = start + entry.compressedSize;
  if (end > bytes.length) throw truncated(`${entry.displayName}: needs ${entry.compressedSize} bytes of data but the file ends ${end - bytes.length} bytes short. The archive is truncated.`);
  return bytes.subarray(start, end);
}

// ---------- ZipCrypto (traditional PKWARE encryption) ----------
function zipCryptoKeys(pw) {
  const k = new Int32Array([0x12345678, 0x23456789, 0x34567890]);
  for (const c of pw) zcUpdate(k, c);
  return k;
}
function zcUpdate(k, c) {
  k[0] = CRC_TABLE[(k[0] ^ c) & 0xff] ^ (k[0] >>> 8);
  k[1] = Math.imul(k[1] + (k[0] & 0xff), 134775813) + 1;
  k[2] = CRC_TABLE[(k[2] ^ (k[1] >>> 24)) & 0xff] ^ (k[2] >>> 8);
}
function zcDecrypt(k, src, dst) {
  for (let i = 0; i < src.length; i++) {
    const t = (k[2] | 2) & 0xffff;
    const c = src[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff);
    dst[i] = c; zcUpdate(k, c);
  }
}
// The 12-byte encryption header ends with a check byte: the CRC's high byte, or
// the modification time's high byte when sizes follow in a data descriptor.
// A wrong password passes this by chance 1 time in 256; the CRC catches those.
function zipCryptoOpen(data, entry, pw) {
  if (data.length < 12) throw corrupt(`${entry.displayName}: encrypted data is shorter than its 12-byte header.`);
  const k = zipCryptoKeys(pw);
  const head = new Uint8Array(12);
  zcDecrypt(k, data.subarray(0, 12), head);
  const check = head[11];
  if (check !== entry.crc >>> 24 && !((entry.flags & 8) && check === entry.modTime >>> 8)) return null;
  const out = new Uint8Array(data.length - 12);
  zcDecrypt(k, data.subarray(12), out);
  return out;
}

// ---------- AES (WinZip AE-1 / AE-2: PBKDF2-HMAC-SHA1, AES-CTR, HMAC-SHA1) ----------
const SBOX = new Uint8Array(256), TE = [new Int32Array(256), new Int32Array(256), new Int32Array(256), new Int32Array(256)];
{
  const d = new Uint8Array(256), th = new Uint8Array(256);
  for (let i = 0; i < 256; i++) th[(d[i] = (i << 1) ^ ((i >> 7) * 283)) ^ i] = i;
  for (let x = 0, xInv = 0, x2; !SBOX[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
    let s = xInv ^ (xInv << 1) ^ (xInv << 2) ^ (xInv << 3) ^ (xInv << 4);
    s = (s >> 8) ^ (s & 255) ^ 99;
    SBOX[x] = s;
    x2 = d[x];
    let t = (d[s] * 0x101) ^ (s * 0x1010100);
    for (let i = 0; i < 4; i++) TE[i][x] = t = (t << 24) ^ (t >>> 8);
  }
}
function aesExpandKey(keyBytes) {
  const nk = keyBytes.length / 4, total = 4 * nk + 28;
  const w = new Int32Array(total);
  for (let i = 0; i < nk; i++) w[i] = (keyBytes[4 * i] << 24) | (keyBytes[4 * i + 1] << 16) | (keyBytes[4 * i + 2] << 8) | keyBytes[4 * i + 3];
  for (let i = nk, rcon = 1; i < total; i++) {
    let t = w[i - 1];
    if (i % nk === 0 || (nk === 8 && i % nk === 4)) {
      t = (SBOX[t >>> 24] << 24) ^ (SBOX[(t >> 16) & 255] << 16) ^ (SBOX[(t >> 8) & 255] << 8) ^ SBOX[t & 255];
      if (i % nk === 0) { t = (t << 8) ^ (t >>> 24) ^ (rcon << 24); rcon = (rcon << 1) ^ ((rcon >> 7) * 283); }
    }
    w[i] = w[i - nk] ^ t;
  }
  return w;
}
/** Encrypt one 16-byte block (exported for the known-answer test). */
export function aesEncryptBlock(w, inp, out) {
  const [t0, t1, t2, t3] = TE;
  const rd = (i) => (inp[i] << 24) | (inp[i + 1] << 16) | (inp[i + 2] << 8) | inp[i + 3];
  let a = rd(0) ^ w[0], b = rd(4) ^ w[1], c = rd(8) ^ w[2], d = rd(12) ^ w[3];
  const rounds = w.length / 4 - 2;
  let k = 4;
  for (let r = 0; r < rounds; r++) {
    const a2 = t0[a >>> 24] ^ t1[(b >> 16) & 255] ^ t2[(c >> 8) & 255] ^ t3[d & 255] ^ w[k];
    const b2 = t0[b >>> 24] ^ t1[(c >> 16) & 255] ^ t2[(d >> 8) & 255] ^ t3[a & 255] ^ w[k + 1];
    const c2 = t0[c >>> 24] ^ t1[(d >> 16) & 255] ^ t2[(a >> 8) & 255] ^ t3[b & 255] ^ w[k + 2];
    d = t0[d >>> 24] ^ t1[(a >> 16) & 255] ^ t2[(b >> 8) & 255] ^ t3[c & 255] ^ w[k + 3];
    k += 4; a = a2; b = b2; c = c2;
  }
  for (let i = 0; i < 4; i++) {
    const v = (SBOX[a >>> 24] << 24) ^ (SBOX[(b >> 16) & 255] << 16) ^ (SBOX[(c >> 8) & 255] << 8) ^ SBOX[d & 255] ^ w[k++];
    out[4 * i] = v >>> 24; out[4 * i + 1] = (v >> 16) & 255; out[4 * i + 2] = (v >> 8) & 255; out[4 * i + 3] = v & 255;
    const t = a; a = b; b = c; c = d; d = t;
  }
}
export { aesExpandKey };
function hmacSha1(key, msg) {
  const k = new Uint8Array(64);
  k.set(key.length > 64 ? sha1Bytes(key) : key);
  const inner = new Uint8Array(64 + msg.length);
  for (let i = 0; i < 64; i++) inner[i] = k[i] ^ 0x36;
  inner.set(msg, 64);
  const outer = new Uint8Array(84);
  for (let i = 0; i < 64; i++) outer[i] = k[i] ^ 0x5c;
  outer.set(sha1Bytes(inner), 64);
  return sha1Bytes(outer);
}
export function pbkdf2Sha1(pw, salt, iterations, length) {
  const out = new Uint8Array(length);
  const block = new Uint8Array(salt.length + 4);
  block.set(salt);
  for (let n = 1, pos = 0; pos < length; n++, pos += 20) {
    block[salt.length] = n >>> 24; block[salt.length + 1] = n >>> 16; block[salt.length + 2] = n >>> 8; block[salt.length + 3] = n;
    let u = hmacSha1(pw, block);
    const t = u.slice();
    for (let i = 1; i < iterations; i++) { u = hmacSha1(pw, u); for (let j = 0; j < 20; j++) t[j] ^= u[j]; }
    out.set(t.subarray(0, Math.min(20, length - pos)), pos);
  }
  return out;
}
function aesOpen(data, entry, pw, verifyMac) {
  const keyLen = [0, 16, 24, 32][entry.aes.strength];
  if (!keyLen) throw new ZipError('unsupported', `${entry.displayName}: unknown AES strength ${entry.aes.strength}.`);
  const saltLen = keyLen / 2;
  if (data.length < saltLen + 2 + 10) throw corrupt(`${entry.displayName}: AES data is shorter than its salt, verifier and authentication code.`);
  const dk = pbkdf2Sha1(pw, data.subarray(0, saltLen), 1000, 2 * keyLen + 2);
  if (dk[2 * keyLen] !== data[saltLen] || dk[2 * keyLen + 1] !== data[saltLen + 1]) return null;
  const cipher = data.subarray(saltLen + 2, data.length - 10);
  if (verifyMac) {
    const mac = hmacSha1(dk.subarray(keyLen, 2 * keyLen), cipher), stored = data.subarray(data.length - 10);
    for (let i = 0; i < 10; i++) if (mac[i] !== stored[i]) throw new ZipError('crc', `${entry.displayName}: the AES authentication code does not match. The archive is damaged or was tampered with.`);
  }
  const w = aesExpandKey(dk.subarray(0, keyLen));
  const out = new Uint8Array(cipher.length), ctr = new Uint8Array(16), ks = new Uint8Array(16);
  for (let off = 0; off < cipher.length; off += 16) {
    for (let i = 0; i < 16; i++) { ctr[i] = (ctr[i] + 1) & 255; if (ctr[i]) break; } // little-endian counter, starting at 1
    aesEncryptBlock(w, ctr, ks);
    const n = Math.min(16, cipher.length - off);
    for (let i = 0; i < n; i++) out[off + i] = cipher[off + i] ^ ks[i];
  }
  return out;
}

// ---------- DEFLATE (RFC 1951) ----------
const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CLORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// Canonical Huffman code -> direct lookup table indexed by the next `bits` input bits
// (LSB first). Entry = symbol << 4 | code length; 0 marks an unused (invalid) code.
function huffTable(lengths) {
  const counts = new Uint16Array(16);
  let max = 0;
  for (const l of lengths) if (l) { counts[l]++; if (l > max) max = l; }
  if (!max) return { bits: 1, table: new Uint32Array(2) };
  for (let l = 1, left = 1; l <= 15; l++) { left = (left << 1) - counts[l]; if (left < 0) throw corrupt('DEFLATE data is damaged (over-subscribed Huffman code).'); }
  const next = new Uint16Array(16);
  for (let l = 1, code = 0; l <= 15; l++) { code = (code + counts[l - 1]) << 1; next[l] = code; }
  const size = 1 << max, table = new Uint32Array(size);
  for (let sym = 0; sym < lengths.length; sym++) {
    const l = lengths[sym];
    if (!l) continue;
    let c = next[l]++, r = 0;
    for (let i = 0; i < l; i++) { r = (r << 1) | (c & 1); c >>= 1; }
    for (let i = r; i < size; i += 1 << l) table[i] = (sym << 4) | l;
  }
  return { bits: max, table };
}
let FIXED = null;
function fixedTables() {
  if (!FIXED) {
    const l = new Uint8Array(288);
    l.fill(8, 0, 144); l.fill(9, 144, 256); l.fill(7, 256, 280); l.fill(8, 280, 288);
    FIXED = { lit: huffTable(l), dist: huffTable(new Uint8Array(30).fill(5)) };
  }
  return FIXED;
}

/**
 * Inflate raw DEFLATE data. Throws ZipError('corrupt' | 'truncated') on bad
 * input and ZipError('too-big') if the output would exceed maxOut. With stopAt,
 * returns as soon as that many bytes exist (used to sniff an entry's first bytes).
 */
export function inflateRaw(src, { maxOut = MAX_EXTRACT, stopAt = 0, sizeHint = 0 } = {}) {
  const len = src.length;
  let pos = 0, bitbuf = 0, bitcnt = 0;
  let out = new Uint8Array(Math.max(1024, Math.min(sizeHint || len * 4, maxOut, 1 << 24))), olen = 0;
  const need = (n) => { while (bitcnt < n) { if (pos >= len) throw truncated('DEFLATE data ends early; the entry is truncated.'); bitbuf |= src[pos++] << bitcnt; bitcnt += 8; } };
  const bits = (n) => { need(n); const v = bitbuf & ((1 << n) - 1); bitbuf >>>= n; bitcnt -= n; return v; };
  const decode = (h) => {
    while (bitcnt < h.bits && pos < len) { bitbuf |= src[pos++] << bitcnt; bitcnt += 8; }
    const e = h.table[bitbuf & ((1 << h.bits) - 1)], l = e & 15;
    if (!l) throw corrupt('DEFLATE data is damaged (invalid Huffman code).');
    if (l > bitcnt) throw truncated('DEFLATE data ends early; the entry is truncated.');
    bitbuf >>>= l; bitcnt -= l;
    return e >>> 4;
  };
  const room = (n) => {
    if (olen + n > maxOut) throw new ZipError('too-big', `decompresses to more than ${maxOut} bytes`);
    if (olen + n <= out.length) return;
    const grown = new Uint8Array(Math.min(maxOut, Math.max(out.length * 2, olen + n)));
    grown.set(out.subarray(0, olen)); out = grown;
  };
  const done = () => stopAt && olen >= stopAt;

  let final = 0;
  do {
    final = bits(1);
    const type = bits(2);
    if (type === 0) {
      pos -= bitcnt >>> 3; bitbuf = 0; bitcnt = 0; // drop the partial byte, give back whole buffered bytes
      if (pos + 4 > len) throw truncated('DEFLATE data ends early; the entry is truncated.');
      const n = src[pos] | (src[pos + 1] << 8), nn = src[pos + 2] | (src[pos + 3] << 8);
      if (n !== (~nn & 0xffff)) throw corrupt('DEFLATE data is damaged (stored block length check failed).');
      pos += 4;
      if (pos + n > len) throw truncated('DEFLATE data ends early; the entry is truncated.');
      room(n); out.set(src.subarray(pos, pos + n), olen); olen += n; pos += n;
      if (done()) break;
      continue;
    }
    let lit, dist;
    if (type === 1) ({ lit, dist } = fixedTables());
    else if (type === 2) {
      const nlen = bits(5) + 257, ndist = bits(5) + 1, ncode = bits(4) + 4;
      if (nlen > 286 || ndist > 30) throw corrupt('DEFLATE data is damaged (bad code counts).');
      const cl = new Uint8Array(19);
      for (let i = 0; i < ncode; i++) cl[CLORDER[i]] = bits(3);
      const clh = huffTable(cl);
      const all = new Uint8Array(nlen + ndist);
      for (let i = 0; i < all.length;) {
        const sym = decode(clh);
        if (sym < 16) { all[i++] = sym; continue; }
        let rep, val = 0;
        if (sym === 16) { if (!i) throw corrupt('DEFLATE data is damaged (repeat with no previous length).'); val = all[i - 1]; rep = 3 + bits(2); }
        else if (sym === 17) rep = 3 + bits(3);
        else rep = 11 + bits(7);
        if (i + rep > all.length) throw corrupt('DEFLATE data is damaged (code lengths overrun).');
        all.fill(val, i, i + rep); i += rep;
      }
      if (!all[256]) throw corrupt('DEFLATE data is damaged (no end-of-block code).');
      lit = huffTable(all.subarray(0, nlen)); dist = huffTable(all.subarray(nlen));
    } else throw corrupt('DEFLATE data is damaged (invalid block type 3).');
    for (;;) {
      let sym = decode(lit);
      if (sym < 256) { room(1); out[olen++] = sym; }
      else if (sym === 256) break;
      else {
        sym -= 257;
        if (sym >= 29) throw corrupt('DEFLATE data is damaged (invalid length code).');
        const n = LBASE[sym] + bits(LEXT[sym]);
        const ds = decode(dist);
        if (ds >= 30) throw corrupt('DEFLATE data is damaged (invalid distance code).');
        const d = DBASE[ds] + bits(DEXT[ds]);
        if (d > olen) throw corrupt('DEFLATE data is damaged (distance reaches before the start).');
        room(n);
        for (let k = 0; k < n; k++, olen++) out[olen] = out[olen - d];
      }
      if (done()) break;
    }
    if (done()) break;
  } while (!final);
  return out.slice(0, stopAt ? Math.min(olen, stopAt) : olen);
}

// ---------- extraction ----------
const enc = (pw) => (typeof pw === 'string' ? new TextEncoder().encode(pw) : pw || new Uint8Array(0));

/** Quick password test (ZipCrypto check byte or AES verifier). True for unencrypted entries. */
export function checkPassword(bytes, entry, password) {
  if (!entry.encrypted) return true;
  const data = entryData(bytes, entry);
  if (entry.aes) return aesOpen(data.subarray(0, Math.min(data.length, [0, 8, 12, 16][entry.aes.strength] + 12)), entry, enc(password), false) !== null;
  if (data.length < 12) return false;
  const k = zipCryptoKeys(enc(password)), head = new Uint8Array(12);
  zcDecrypt(k, data.subarray(0, 12), head);
  return head[11] === entry.crc >>> 24 || ((entry.flags & 8) !== 0 && head[11] === entry.modTime >>> 8);
}

/**
 * Extract one entry. Options: password (string), maxSize (cap, default MAX_EXTRACT),
 * prefix (return only the first N bytes, skipping the CRC; for sniffing).
 * Throws ZipError: need-password, bad-password, too-big, crc, corrupt, truncated, unsupported.
 */
export function extractEntry(bytes, entry, { password, maxSize = MAX_EXTRACT, prefix = 0 } = {}) {
  const name = entry.displayName;
  if (entry.dir) throw new ZipError('unsupported', `${name} is a folder.`);
  if (entry.encrypted && entry.encryption === 'PKWARE strong encryption') throw new ZipError('unsupported', `${name} uses PKWARE strong encryption, which Peek cannot open. Re-pack it with 7-Zip (ZipCrypto or AES).`);
  if (entry.method !== 0 && entry.method !== 8) throw new ZipError('unsupported', `${name} is compressed with ${entry.methodName}; Peek handles stored and deflate entries. Re-pack it with deflate, or extract it with 7-Zip.`);
  if (entry.size > maxSize) throw new ZipError('too-big', `${name} would unpack to ${entry.size} bytes, over Peek's ${maxSize}-byte limit. Possibly a zip bomb; not extracted.`);
  let data = entryData(bytes, entry);
  if (entry.encrypted) {
    if (password === undefined || password === null) throw new ZipError('need-password', `${name} is encrypted.`);
    const opened = entry.aes ? aesOpen(data, entry, enc(password), !prefix) : zipCryptoOpen(data, entry, enc(password));
    if (!opened) throw new ZipError('bad-password', `Wrong password for ${name}.`);
    data = opened;
  }
  let out;
  if (entry.method === 0) {
    if (!prefix && data.length !== entry.size) throw corrupt(`${name}: stored entry is ${data.length} bytes but the directory says ${entry.size}.`);
    out = data.slice(0, prefix ? Math.min(prefix, data.length) : data.length);
  } else {
    try { out = inflateRaw(data, { maxOut: entry.size, stopAt: prefix, sizeHint: entry.size }); }
    catch (e) {
      if (!(e instanceof ZipError)) throw e;
      // ZipCrypto passes a wrong password 1 time in 256; the garbage then fails to inflate.
      if (entry.encrypted && !entry.aes && e.code !== 'too-big') throw new ZipError('bad-password', `Wrong password for ${name} (or the entry is damaged): ${e.message}`);
      if (e.code === 'too-big') throw new ZipError('too-big', `${name} inflates past the ${entry.size} bytes its header declares. A zip bomb or a damaged archive; extraction stopped.`);
      throw new ZipError(e.code, `${name}: ${e.message}`);
    }
    if (!prefix && out.length !== entry.size) throw corrupt(`${name}: unpacked to ${out.length} bytes but the directory says ${entry.size}.`);
  }
  // AE-2 stores no CRC (the HMAC covers integrity); everything else must match.
  if (!prefix && !(entry.aes && entry.aes.version === 2)) {
    const c = crc32(out);
    if (c !== entry.crc) {
      if (entry.encrypted && !entry.aes) throw new ZipError('bad-password', `Wrong password for ${name}: the unpacked data fails its CRC check.`);
      throw new ZipError('crc', `${name}: CRC mismatch (expected ${entry.crc.toString(16).padStart(8, '0')}, got ${c.toString(16).padStart(8, '0')}). The archive is damaged.`);
    }
  }
  return out;
}

/** 'pe' (MZ with a PE signature), 'mz' (MZ header only, e.g. DOS or the PE header lies beyond the sniffed bytes) or 'other'. */
export function sniffKind(head) {
  if (head.length < 2 || head[0] !== 0x4d || head[1] !== 0x5a) return 'other';
  if (head.length < 0x40) return 'mz';
  const lfanew = (head[0x3c] | (head[0x3d] << 8) | (head[0x3e] << 16) | (head[0x3f] << 24)) >>> 0;
  if (lfanew + 4 > head.length) return 'mz';
  return head[lfanew] === 0x50 && head[lfanew + 1] === 0x45 && !head[lfanew + 2] && !head[lfanew + 3] ? 'pe' : 'mz';
}

/**
 * Try each password against the first encrypted entry. Returns the one that
 * works, '' when nothing is encrypted, or null when none fit.
 */
export function findPassword(bytes, entries, candidates = DEFAULT_PASSWORDS) {
  const enc1 = entries.find((e) => e.encrypted && !e.dir);
  if (!enc1) return '';
  for (const pw of candidates) if (checkPassword(bytes, enc1, pw)) return pw;
  return null;
}

/**
 * Sniff every file entry: { entry, kind: 'pe'|'mz'|'other'|'error', error? }.
 * Reads at most `prefix` bytes of each, so a big archive stays cheap.
 */
export function classifyEntries(bytes, entries, password, prefix = 64 * 1024) {
  return entries.filter((e) => !e.dir).map((entry) => {
    try { return { entry, kind: sniffKind(extractEntry(bytes, entry, { password, prefix })) }; }
    catch (e) { if (!(e instanceof ZipError)) throw e; return { entry, kind: 'error', error: e }; }
  });
}
