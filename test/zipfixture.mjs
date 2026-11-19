// Builds ZIP archives for the tests, so no archive (and no sample inside one) is
// committed. The encryption here is written independently of src/zip.js:
// ZipCrypto from the APPNOTE description, AES via node:crypto, deflate via node:zlib.
import { deflateRawSync } from 'node:zlib';
import { createCipheriv, createHmac, pbkdf2Sync, randomBytes } from 'node:crypto';

const CRC = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
export function crc(buf) { let c = 0xffffffff; for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

function zipCryptoEncrypt(pw, plain, checkByte) {
  let k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
  const upd = (c) => {
    k0 = (CRC[(k0 ^ c) & 0xff] ^ (k0 >>> 8)) >>> 0;
    k1 = (Number((BigInt(k1) + BigInt(k0 & 0xff)) * 134775813n + 1n & 0xffffffffn)) >>> 0;
    k2 = (CRC[(k2 ^ (k1 >>> 24)) & 0xff] ^ (k2 >>> 8)) >>> 0;
  };
  for (const c of Buffer.from(pw)) upd(c);
  const head = randomBytes(12); head[11] = checkByte;
  const src = Buffer.concat([head, plain]), out = Buffer.alloc(src.length);
  for (let i = 0; i < src.length; i++) { const t = (k2 | 2) & 0xffff; out[i] = src[i] ^ ((t * (t ^ 1)) >>> 8 & 0xff); upd(src[i]); }
  return out;
}

function aesEncrypt(pw, plain, strength = 3) {
  const keyLen = [0, 16, 24, 32][strength], salt = randomBytes(keyLen / 2);
  const dk = pbkdf2Sync(Buffer.from(pw), salt, 1000, 2 * keyLen + 2, 'sha1');
  const ecb = createCipheriv(`aes-${keyLen * 8}-ecb`, dk.subarray(0, keyLen), null); ecb.setAutoPadding(false);
  const out = Buffer.alloc(plain.length), ctr = Buffer.alloc(16);
  for (let off = 0; off < plain.length; off += 16) {
    for (let i = 0; i < 16; i++) if (++ctr[i] !== 256) break; else ctr[i] = 0; // little-endian counter from 1
    const ks = ecb.update(ctr);
    for (let i = 0; i < 16 && off + i < plain.length; i++) out[off + i] = plain[off + i] ^ ks[i];
  }
  const mac = createHmac('sha1', dk.subarray(keyLen, 2 * keyLen)).update(out).digest().subarray(0, 10);
  return Buffer.concat([salt, dk.subarray(2 * keyLen), out, mac]);
}

/**
 * makeZip([{ name, data, method: 'deflate'|'store', encryption: 'none'|'zipcrypto'|'aes', aesVersion: 1|2, password, size?, crc? }])
 * `size` / `crc` override what the directory declares (for lying-header tests).
 */
export function makeZip(files, { comment = '' } = {}) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const f of files) {
    const data = Buffer.from(f.data);
    const encryption = f.encryption || 'none', pw = f.password ?? 'infected';
    const method = f.method === 'store' ? 0 : 8;
    const body = method === 8 ? deflateRawSync(data) : data;
    const c = f.crc ?? crc(data);
    const modTime = 0x6000, modDate = 0x5a21;
    let payload = body, flags = 0x800, zipMethod = method, extra = Buffer.alloc(0);
    if (encryption === 'zipcrypto') { flags |= 1; payload = zipCryptoEncrypt(pw, body, c >>> 24); }
    if (encryption === 'aes') {
      flags |= 1; zipMethod = 99; payload = aesEncrypt(pw, body, f.strength || 3);
      extra = Buffer.alloc(11);
      extra.writeUInt16LE(0x9901, 0); extra.writeUInt16LE(7, 2); extra.writeUInt16LE(f.aesVersion || 2, 4); extra.write('AE', 6, 'latin1'); extra[8] = f.strength || 3; extra.writeUInt16LE(method, 9);
    }
    const storedCrc = encryption === 'aes' && (f.aesVersion || 2) === 2 ? 0 : c;
    const name = Buffer.from(f.name);
    const size = f.size ?? data.length;
    const fields = (sig, central) => {
      const h = Buffer.alloc(central ? 46 : 30);
      h.writeUInt32LE(sig, 0);
      let p = 4;
      if (central) { h.writeUInt16LE(0x033f, p); p += 2; }
      h.writeUInt16LE(central ? 51 : 51, p); h.writeUInt16LE(flags, p + 2); h.writeUInt16LE(zipMethod, p + 4); h.writeUInt16LE(modTime, p + 6); h.writeUInt16LE(modDate, p + 8);
      h.writeUInt32LE(storedCrc, p + 10); h.writeUInt32LE(payload.length, p + 14); h.writeUInt32LE(size, p + 18); h.writeUInt16LE(name.length, p + 22); h.writeUInt16LE(extra.length, p + 24);
      if (central) h.writeUInt32LE(offset, 42);
      return Buffer.concat([h, name, extra]);
    };
    const local = Buffer.concat([fields(0x04034b50, false), payload]);
    centrals.push(fields(0x02014b50, true));
    locals.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(centrals), com = Buffer.from(comment);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16); end.writeUInt16LE(com.length, 20);
  return new Uint8Array(Buffer.concat([...locals, cd, end, com]));
}
