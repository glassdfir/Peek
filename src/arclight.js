// Case 01's "update.exe" (jon.glass/cases/arclight/): fake and safe, not a program.
// Copied verbatim from Hexes (glassdfir/hexes, buildArclight) so both tools open the same
// bytes. The case's logs pin this file's SHA-256 and size, and test/arclight.test.mjs
// fails if this copy ever drifts from them. If Hexes' generator changes, copy it again.
function crc32(u8) {
  let c, crc = 0xffffffff;
  for (let i = 0; i < u8.length; i++) {
    c = (crc ^ u8[i]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}
export function buildArclight() {
  let seed = 0x1013;
  const rnd = () => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 24);
  const enc = t => Uint8Array.from(t, c => c.charCodeAt(0) & 255);
  const wide = t => { const o = new Uint8Array(t.length * 2); for (let i = 0; i < t.length; i++) o[i * 2] = t.charCodeAt(i); return o; };
  const b64 = u8 => btoa(String.fromCharCode(...u8));
  const ft = ms => (BigInt(ms) + 11644473600000n) * 10000n;
  const parts = [];

  // headers: MZ, DOS stub, PE x64 with a build time four days before the phish
  const hdr = new Uint8Array(0x400), dv = new DataView(hdr.buffer);
  hdr.set(enc('MZ'), 0); dv.setUint16(2, 0x90, true); dv.setUint32(0x3c, 0x80, true);
  hdr.set(enc('This program cannot be run in DOS mode.\r\r\n$'), 0x4e);
  hdr.set(enc('PE\0\0'), 0x80);
  dv.setUint16(0x84, 0x8664, true); dv.setUint16(0x86, 4, true);
  dv.setUint32(0x88, Math.floor(Date.UTC(2026, 9, 9, 22, 14, 5) / 1000), true);
  dv.setUint16(0x94, 0xf0, true); dv.setUint16(0x96, 0x0022, true); dv.setUint16(0x98, 0x020b, true);
  ['.text', '.rdata', '.data', '.rsrc'].forEach((n, i) => hdr.set(enc(n), 0x188 + i * 40));
  parts.push(hdr);

  // .text: honest about what this is, then filler that looks like code padding
  const text = new Uint8Array(0x2000);
  text.set(enc('Arclight Industries case evidence for jon.glass/cases/arclight. Fake and safe: this is not a program.\0'), 0);
  const ops = [0x48, 0x89, 0x8b, 0xe8, 0xff, 0x0f, 0x85, 0x84, 0xc3, 0x90, 0x83, 0xc4, 0x8d, 0x4c, 0x24, 0x00]; // common x64 bytes
  for (let i = 0x80; i < text.length; i++) text[i] = i % 32 < 28 ? ops[rnd() & 15] : 0xcc;
  parts.push(text);

  // .rdata: plain strings, then UTF-16 ones
  parts.push(enc([
    'Global\\tf-1013-mtx', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36',
    '/api/v2/sync', 'POST', 'application/octet-stream', '%APPDATA%\\Microsoft\\Teams\\update.exe', 'TeamsUpdater', 'ArcUpdSvc',
  ].join('\0') + '\0\0\0\0'));
  [ 'C:\\ProgramData\\d.bin', 'comsvcs.dll, MiniDump', 'C:\\Windows\\Temp\\arcupd.exe', '\\\\FILE-01\\ADMIN$' ]
    .forEach(t => parts.push(wide(t), new Uint8Array(4)));
  parts.push(new Uint8Array(0x600));

  // .data: the config XOR-ed with 0x37, a FILETIME kill date, and the persistence command as Base64 UTF-16
  const cfg = 'c2=203.0.113.66:443;path=/api/v2/sync;sleep=60;jitter=20;task=TeamsUpdater;svc=ArcUpdSvc;campaign=TF-1013;exfil=https://198.51.100.77/upload';
  parts.push(enc('cfg1:'), enc(cfg).map(x => x ^ 0x37), new Uint8Array(3));
  const kd = new Uint8Array(8); new DataView(kd.buffer).setBigUint64(0, ft(Date.UTC(2026, 10, 13)), true);
  parts.push(enc('kd:'), kd, new Uint8Array(5));
  parts.push(enc('cfg2=' + b64(wide('schtasks /create /tn TeamsUpdater /tr "%APPDATA%\\Microsoft\\Teams\\update.exe" /sc onlogon /f')) + '\0'));
  parts.push(new Uint8Array(0x800));

  // .rsrc: a real, stored ZIP holding the exfil tool's config. Carve it and it opens.
  const name = enc('rclone.conf'), body = enc('[tf]\ntype = webdav\nurl = https://198.51.100.77/upload\nvendor = other\nuser = tf1013\n');
  const crc = crc32(body), when = [0x8a, 0x6c, 0x4d, 0x5d]; // DOS time 13:36:20, date 2026-10-13
  const lh = new Uint8Array(30), lv = new DataView(lh.buffer);
  lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lh.set(when, 10);
  lv.setUint32(14, crc, true); lv.setUint32(18, body.length, true); lv.setUint32(22, body.length, true); lv.setUint16(26, name.length, true);
  const ch = new Uint8Array(46), cv = new DataView(ch.buffer);
  cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); ch.set(when, 12);
  cv.setUint32(16, crc, true); cv.setUint32(20, body.length, true); cv.setUint32(24, body.length, true); cv.setUint16(28, name.length, true);
  const eo = new Uint8Array(22), ev = new DataView(eo.buffer), zipLen = 30 + name.length + body.length;
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, 1, true); ev.setUint16(10, 1, true);
  ev.setUint32(12, 46 + name.length, true); ev.setUint32(16, zipLen, true);
  parts.push(new Uint8Array(0x200), lh, name, body, ch, name, eo, new Uint8Array(0x200));

  // the encrypted next stage: 96 KiB of high entropy
  const st3 = new Uint8Array(96 * 1024); for (let i = 0; i < st3.length; i++) st3[i] = rnd();
  parts.push(st3, new Uint8Array(0x1000));

  const total = parts.reduce((n, p) => n + p.length, 0), out = new Uint8Array(total);
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
