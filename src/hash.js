// Pure-JS MD5 / SHA-1 / SHA-256 over a Uint8Array. No WebCrypto so the same
// code runs in the browser, the single-file build, Node tests and the CLI,
// and so MD5 (needed for imphash and the Rich header hash) is available.

function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

// Feed 64-byte blocks to fn: full blocks straight from the input, then the
// padded tail (1-2 blocks) built in a scratch buffer. Length is appended as
// 64-bit little-endian (MD5) or big-endian (SHA).
function blocks(bytes, littleEndianLength, fn) {
  const n = bytes.length;
  const full = n - (n % 64);
  for (let off = 0; off < full; off += 64) fn(bytes, off);
  const rem = n - full;
  const tailLen = rem + 9 <= 64 ? 64 : 128;
  const tail = new Uint8Array(tailLen);
  tail.set(bytes.subarray(full), 0);
  tail[rem] = 0x80;
  const bits = n * 8;
  const lo = bits >>> 0;
  const hi = Math.floor(bits / 0x100000000) >>> 0;
  const dv = new DataView(tail.buffer);
  if (littleEndianLength) { dv.setUint32(tailLen - 8, lo, true); dv.setUint32(tailLen - 4, hi, true); }
  else { dv.setUint32(tailLen - 8, hi, false); dv.setUint32(tailLen - 4, lo, false); }
  for (let off = 0; off < tailLen; off += 64) fn(tail, off);
}

const hex8 = (x) => (x >>> 0).toString(16).padStart(8, '0');
const hex8le = (x) => hex8(((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x >>> 8) & 0xff00) | (x >>> 24));

const MD5_K = new Uint32Array(64);
for (let i = 0; i < 64; i++) MD5_K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];

export function md5(bytes) {
  if (typeof bytes === 'string') bytes = new TextEncoder().encode(bytes);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  blocks(bytes, true, (b, off) => {
    for (let i = 0; i < 16; i++) M[i] = b[off + i * 4] | (b[off + i * 4 + 1] << 8) | (b[off + i * 4 + 2] << 16) | (b[off + i * 4 + 3] << 24);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + MD5_K[i] + M[g]) >>> 0;
      A = D; D = C; C = B; B = (B + rotl(F, MD5_S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  });
  return hex8le(a0) + hex8le(b0) + hex8le(c0) + hex8le(d0);
}

export function sha1(bytes) {
  return Array.from(sha1Bytes(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}

// Raw 20-byte SHA-1 digest, for HMAC/PBKDF2 in the ZIP reader (WinZip AES).
export function sha1Bytes(bytes) {
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const W = new Uint32Array(80);
  blocks(bytes, false, (b, off) => {
    for (let i = 0; i < 16; i++) W[i] = (b[off + i * 4] << 24) | (b[off + i * 4 + 1] << 16) | (b[off + i * 4 + 2] << 8) | b[off + i * 4 + 3];
    for (let i = 16; i < 80; i++) W[i] = rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    let a = h0, b2 = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b2 & c) | (~b2 & d); k = 0x5a827999; }
      else if (i < 40) { f = b2 ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b2 & c) | (b2 & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b2 ^ c ^ d; k = 0xca62c1d6; }
      const t = (rotl(a, 5) + f + e + k + W[i]) >>> 0;
      e = d; d = c; c = rotl(b2, 30); b2 = a; a = t;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b2) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
  });
  const out = new Uint8Array(20), dv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4].forEach((v, i) => dv.setUint32(i * 4, v, false));
  return out;
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

export function sha256(bytes) {
  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  blocks(bytes, false, (b, off) => {
    for (let i = 0; i < 16; i++) W[i] = (b[off + i * 4] << 24) | (b[off + i * 4 + 1] << 16) | (b[off + i * 4 + 2] << 8) | b[off + i * 4 + 3];
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let a = H[0], b2 = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b2) ^ (a & c) ^ (b2 & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b2; b2 = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b2) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  });
  return Array.from(H, hex8).join('');
}

// Shannon entropy in bits per byte (0..8).
export function entropy(bytes) {
  if (!bytes || bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let e = 0;
  const n = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (!counts[i]) continue;
    const p = counts[i] / n;
    e -= p * Math.log2(p);
  }
  return e;
}
