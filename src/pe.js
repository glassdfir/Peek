// Tolerant Portable Executable parser. Pure: no DOM, no Node APIs, so the
// same module runs in the browser, in tests and in the CLI.
//
// Design rules (malware deliberately breaks headers, so the parser must not):
//  - every read is bounds-checked and throws PEError past EOF
//  - every directory is parsed inside safe(); a failure records a warning and
//    keeps whatever was parsed so far
//  - counts are capped, strings are length-limited, recursion is depth-limited
//  - nothing is executed or rendered; resources are only inspected

import { md5, sha1, sha256, entropy } from './hash.js';
import { ordinalName } from './ordlookup.js';
import { richProductName, richToolchain } from './richids.js';

export class PEError extends Error {}

// ---------- constants ----------
export const MACHINES = {
  0x0: 'Unknown', 0x14c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0x1c0: 'ARM', 0x1c2: 'ARM Thumb', 0x1c4: 'ARM Thumb-2 (ARMNT)',
  0xaa64: 'ARM64', 0xa641: 'ARM64EC', 0xa64e: 'ARM64X', 0x3a64: 'CHPE x86', 0x200: 'Itanium (IA64)', 0xebc: 'EFI byte code',
  0x166: 'MIPS R4000', 0x169: 'MIPS WCE v2', 0x1f0: 'PowerPC', 0x1f1: 'PowerPC FP', 0x5032: 'RISC-V 32', 0x5064: 'RISC-V 64',
  0x5128: 'RISC-V 128', 0x6232: 'LoongArch 32', 0x6264: 'LoongArch 64', 0x9041: 'M32R', 0x1a2: 'SH3', 0x1a6: 'SH4', 0x1a8: 'SH5',
  0x266: 'MIPS16', 0x366: 'MIPS FPU', 0x466: 'MIPS16 FPU', 0x184: 'Alpha AXP', 0x284: 'Alpha 64',
};
export const FILE_CHARACTERISTICS = [
  [0x0001, 'RELOCS_STRIPPED'], [0x0002, 'EXECUTABLE_IMAGE'], [0x0004, 'LINE_NUMS_STRIPPED'], [0x0008, 'LOCAL_SYMS_STRIPPED'],
  [0x0010, 'AGGRESSIVE_WS_TRIM'], [0x0020, 'LARGE_ADDRESS_AWARE'], [0x0080, 'BYTES_REVERSED_LO'], [0x0100, '32BIT_MACHINE'],
  [0x0200, 'DEBUG_STRIPPED'], [0x0400, 'REMOVABLE_RUN_FROM_SWAP'], [0x0800, 'NET_RUN_FROM_SWAP'], [0x1000, 'SYSTEM'],
  [0x2000, 'DLL'], [0x4000, 'UP_SYSTEM_ONLY'], [0x8000, 'BYTES_REVERSED_HI'],
];
export const SUBSYSTEMS = {
  0: 'Unknown', 1: 'Native', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console', 7: 'POSIX console', 8: 'Native Win9x driver',
  9: 'Windows CE GUI', 10: 'EFI application', 11: 'EFI boot service driver', 12: 'EFI runtime driver', 13: 'EFI ROM', 14: 'Xbox',
  16: 'Windows boot application',
};
export const DLL_CHARACTERISTICS = [
  [0x0020, 'HIGH_ENTROPY_VA'], [0x0040, 'DYNAMIC_BASE'], [0x0080, 'FORCE_INTEGRITY'], [0x0100, 'NX_COMPAT'], [0x0200, 'NO_ISOLATION'],
  [0x0400, 'NO_SEH'], [0x0800, 'NO_BIND'], [0x1000, 'APPCONTAINER'], [0x2000, 'WDM_DRIVER'], [0x4000, 'GUARD_CF'], [0x8000, 'TERMINAL_SERVER_AWARE'],
];
export const SECTION_FLAGS = [
  [0x00000008, 'TYPE_NO_PAD'], [0x00000020, 'CNT_CODE'], [0x00000040, 'CNT_INITIALIZED_DATA'], [0x00000080, 'CNT_UNINITIALIZED_DATA'],
  [0x00000200, 'LNK_INFO'], [0x00000800, 'LNK_REMOVE'], [0x00001000, 'LNK_COMDAT'], [0x00008000, 'GPREL'], [0x01000000, 'LNK_NRELOC_OVFL'],
  [0x02000000, 'MEM_DISCARDABLE'], [0x04000000, 'MEM_NOT_CACHED'], [0x08000000, 'MEM_NOT_PAGED'], [0x10000000, 'MEM_SHARED'],
  [0x20000000, 'MEM_EXECUTE'], [0x40000000, 'MEM_READ'], [0x80000000, 'MEM_WRITE'],
];
export const DIRECTORY_NAMES = ['Export', 'Import', 'Resource', 'Exception', 'Security', 'Base relocation', 'Debug', 'Architecture',
  'Global pointer', 'TLS', 'Load config', 'Bound import', 'IAT', 'Delay import', 'CLR runtime', 'Reserved'];
export const DEBUG_TYPES = { 0: 'Unknown', 1: 'COFF', 2: 'CodeView', 3: 'FPO', 4: 'Misc', 5: 'Exception', 6: 'Fixup', 7: 'OMAP to src',
  8: 'OMAP from src', 9: 'Borland', 10: 'Reserved', 11: 'CLSID', 12: 'VC feature', 13: 'POGO', 14: 'ILTCG', 15: 'MPX', 16: 'Repro',
  17: 'Embedded PDB', 19: 'SPGO', 20: 'Ex DLL characteristics' };
export const RESOURCE_TYPES = { 1: 'CURSOR', 2: 'BITMAP', 3: 'ICON', 4: 'MENU', 5: 'DIALOG', 6: 'STRING', 7: 'FONTDIR', 8: 'FONT',
  9: 'ACCELERATOR', 10: 'RCDATA', 11: 'MESSAGETABLE', 12: 'GROUP_CURSOR', 14: 'GROUP_ICON', 16: 'VERSION', 17: 'DLGINCLUDE',
  19: 'PLUGPLAY', 20: 'VXD', 21: 'ANICURSOR', 22: 'ANIICON', 23: 'HTML', 24: 'MANIFEST' };
const CERT_TYPES = { 0x0001: 'X.509', 0x0002: 'PKCS#7 SignedData (Authenticode)', 0x0003: 'Reserved', 0x0004: 'TS stack signing' };

const MAX_SECTIONS = 96, MAX_IMPORT_DLLS = 1024, MAX_THUNKS = 8192, MAX_TOTAL_THUNKS = 65536, MAX_BAD_NAMES = 32, MAX_BAD_DLLS = 4, MAX_EXPORTS = 65536, MAX_RESOURCE_ENTRIES = 4096;
const MAX_RESOURCE_DEPTH = 4, MAX_DEBUG = 64, MAX_TLS_CALLBACKS = 64, MAX_RELOC_BLOCKS = 100000, MAX_CERTS = 16;

export const flagsOf = (value, table) => table.filter(([bit]) => (value & bit) !== 0).map(([, name]) => name);
export const hex = (n, width = 0) => (n === null || n === undefined ? '' : '0x' + Number(n).toString(16).padStart(width, '0'));
export const alignUp = (n, a) => (a > 0 ? Math.ceil(n / a) * a : n);

// ---------- bounded reader ----------
class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.len = bytes.length;
  }
  check(off, n) {
    if (!Number.isInteger(off) || off < 0 || off + n > this.len) throw new PEError(`read of ${n} bytes at ${hex(off)} is past end of file (${hex(this.len)})`);
  }
  u8(o) { this.check(o, 1); return this.dv.getUint8(o); }
  u16(o) { this.check(o, 2); return this.dv.getUint16(o, true); }
  u32(o) { this.check(o, 4); return this.dv.getUint32(o, true); }
  u64(o) { this.check(o, 8); const v = this.dv.getBigUint64(o, true); return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v; }
  bytes(o, n) { this.check(o, n); return this.b.subarray(o, o + n); }
  // Bytes with the range clamped to the file instead of throwing.
  clamped(o, n) {
    if (!Number.isFinite(o) || o < 0 || o >= this.len || n <= 0) return new Uint8Array(0);
    return this.b.subarray(o, Math.min(this.len, o + n));
  }
  ascii(o, n) { return String.fromCharCode(...this.bytes(o, n)); }
  cstr(o, max = 512) {
    if (o < 0 || o >= this.len) throw new PEError(`string at ${hex(o)} is past end of file`);
    let end = o;
    const lim = Math.min(this.len, o + max);
    while (end < lim && this.b[end] !== 0) end++;
    return latin1(this.b.subarray(o, end));
  }
  utf16z(o, maxChars = 512) {
    let s = '';
    for (let i = 0; i < maxChars; i++) {
      if (o + 2 > this.len) break;
      const c = this.dv.getUint16(o, true);
      if (c === 0) break;
      s += String.fromCharCode(c);
      o += 2;
    }
    return s;
  }
  utf16(o, nChars) { this.check(o, nChars * 2); let s = ''; for (let i = 0; i < nChars; i++) s += String.fromCharCode(this.dv.getUint16(o + i * 2, true)); return s; }
}
const latin1 = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return s; };
const printable = (s) => s.replace(/[^\x20-\x7e]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
const tsIso = (t) => (t === 0 || t === 0xffffffff ? null : new Date(t * 1000).toISOString().replace('.000Z', 'Z'));

// ---------- main ----------
export function parsePE(bytes, opts = {}) {
  if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
  const r = new Reader(bytes);
  const pe = { fileSize: bytes.length, warnings: [], errors: [], sections: [], dataDirectories: [], imports: [], delayImports: [], exports: null, resources: null,
    tls: null, debug: [], clr: null, loadConfig: null, relocations: null, exceptions: null, certificates: null, boundImports: null, overlay: null, rich: null,
    fileHeader: null, optionalHeader: null, entryPoint: null, checksum: null, kind: 'Unknown', hashes: {} };
  // Lookups default to "nothing", so a parse that aborts early still yields an object the UI and analyzer can walk.
  pe.dir = () => null; pe.sectionFor = () => null; pe.rvaToOffset = () => null;
  if (opts.fileHashes !== false) pe.hashes = { md5: md5(bytes), sha1: sha1(bytes), sha256: sha256(bytes) };
  pe.hashes.imphash = null; pe.hashes.richHash = null;
  const warn = (text, level = 'warn') => pe.warnings.push({ level, text });
  const safe = (what, fn) => { try { return fn(); } catch (e) { if (e instanceof PEError || e instanceof RangeError) { warn(`${what}: ${e.message}`); return null; } throw e; } };

  // -- DOS header. Windows only needs the magic and e_lfanew; everything else may overlap or be missing.
  const magic = bytes.length >= 2 ? r.u16(0) : 0;
  if (magic !== 0x5a4d && magic !== 0x4d5a) { pe.errors.push('No MZ signature: not a DOS/PE file.'); return pe; }
  if (magic === 0x4d5a) warn('DOS magic is "ZM" instead of "MZ": accepted by Windows XP and earlier only.', 'error');
  // e_lfanew lives at 0x3c; a file shorter than 0x40 bytes (tiny PEs) still has a usable value in whatever bytes exist.
  let lfanew = 0;
  for (let i = 0; i < 4; i++) if (0x3c + i < bytes.length) lfanew |= bytes[0x3c + i] << (8 * i);
  lfanew >>>= 0;
  pe.dos = { e_magic: magic, e_cblp: bytes.length >= 4 ? r.u16(2) : 0, e_cp: bytes.length >= 6 ? r.u16(4) : 0, e_lfanew: lfanew };
  const nt = lfanew;
  if (nt < 2 || nt + 24 > bytes.length || r.u32(nt) !== 0x00004550) {
    const sig = nt + 2 <= bytes.length && nt >= 2 ? r.ascii(nt, 2) : '';
    const kind = sig === 'NE' ? ' This is a 16-bit NE (Windows 3.x / OS/2) executable.' : sig === 'LE' || sig === 'LX' ? ' This is an LE/LX (VxD / OS/2) executable.' : nt + 24 > bytes.length ? ' e_lfanew points past the end of the file.' : '';
    pe.errors.push(`No PE signature at e_lfanew ${hex(nt)}: DOS executable or corrupt header.${kind}`);
    pe.dosStub = { offset: 0x40, size: Math.max(0, Math.min(nt, bytes.length) - 0x40) };
    return pe;
  }
  if (nt < 0x40) warn(`e_lfanew is ${hex(nt)}: the PE header overlaps the DOS header (tiny-PE technique; Windows accepts it).`, 'error');
  else if (nt > 0x400) warn(`e_lfanew is unusually large (${hex(nt)}); the DOS stub is ${nt - 0x40} bytes.`);
  try { parseImage(r, pe, bytes, nt, opts, warn, safe); }
  catch (e) {
    if (!(e instanceof PEError || e instanceof RangeError)) throw e;
    pe.errors.push(`Parsing stopped: ${e.message}. The headers are truncated or point outside the file; results below are partial.`);
  }
  pe.kind = kindOf(pe);
  return pe;
}

function parseImage(r, pe, bytes, nt, opts, warn, safe) {

  // -- Rich header (between the DOS header and the PE signature)
  pe.rich = safe('Rich header', () => parseRich(r, nt));

  // -- COFF file header
  const fh = nt + 4;
  const machine = r.u16(fh);
  pe.fileHeader = {
    offset: fh, machine, machineName: MACHINES[machine] || `Unknown (${hex(machine)})`,
    numberOfSections: r.u16(fh + 2), timeDateStamp: r.u32(fh + 4), timestamp: tsIso(r.u32(fh + 4)),
    pointerToSymbolTable: r.u32(fh + 8), numberOfSymbols: r.u32(fh + 12), sizeOfOptionalHeader: r.u16(fh + 16),
    characteristics: r.u16(fh + 18),
  };
  pe.fileHeader.characteristicsFlags = flagsOf(pe.fileHeader.characteristics, FILE_CHARACTERISTICS);
  pe.isDll = (pe.fileHeader.characteristics & 0x2000) !== 0;
  pe.isDriver = false;

  // -- Optional header. The loader reads it whatever SizeOfOptionalHeader says; that field only positions the section table.
  const oh = fh + 20;
  const ohSize = pe.fileHeader.sizeOfOptionalHeader;
  const minOh = oh + 2 <= bytes.length && r.u16(oh) === 0x20b ? 0xf0 : 0xe0;
  if (ohSize < minOh) warn(`SizeOfOptionalHeader is ${hex(ohSize)} (normal: ${hex(minOh)}); the section table overlaps the optional header. Windows still loads it.`, ohSize === 0 ? 'error' : 'warn');
  if (oh + 2 > bytes.length) { pe.errors.push('File ends before the optional header.'); }
  else {
    // Tiny PEs (corkami) end inside the optional header and Windows XP still loaded them: missing fields read as 0.
    let ohTruncated = false;
    const T = {
      u8: (o) => (o + 1 <= bytes.length ? r.u8(o) : (ohTruncated = true, 0)), u16: (o) => (o + 2 <= bytes.length ? r.u16(o) : (ohTruncated = true, 0)),
      u32: (o) => (o + 4 <= bytes.length ? r.u32(o) : (ohTruncated = true, 0)), u64: (o) => (o + 8 <= bytes.length ? r.u64(o) : (ohTruncated = true, 0)),
    };
    const magic = T.u16(oh);
    const is64 = magic === 0x20b;
    if (magic !== 0x10b && magic !== 0x20b) warn(`Optional header magic ${hex(magic)} is neither PE32 (0x10b) nor PE32+ (0x20b); parsing as PE32.`, 'error');
    const o = {
      offset: oh, magic, is64, format: is64 ? 'PE32+' : magic === 0x107 ? 'ROM' : 'PE32',
      majorLinkerVersion: T.u8(oh + 2), minorLinkerVersion: T.u8(oh + 3), sizeOfCode: T.u32(oh + 4), sizeOfInitializedData: T.u32(oh + 8),
      sizeOfUninitializedData: T.u32(oh + 12), addressOfEntryPoint: T.u32(oh + 16), baseOfCode: T.u32(oh + 20),
    };
    if (is64) {
      o.imageBase = T.u64(oh + 24);
    } else {
      o.baseOfData = T.u32(oh + 24);
      o.imageBase = T.u32(oh + 28);
    }
    const w = oh + 32; // common part
    Object.assign(o, {
      sectionAlignment: T.u32(w), fileAlignment: T.u32(w + 4), majorOperatingSystemVersion: T.u16(w + 8), minorOperatingSystemVersion: T.u16(w + 10),
      majorImageVersion: T.u16(w + 12), minorImageVersion: T.u16(w + 14), majorSubsystemVersion: T.u16(w + 16), minorSubsystemVersion: T.u16(w + 18),
      win32VersionValue: T.u32(w + 20), sizeOfImage: T.u32(w + 24), sizeOfHeaders: T.u32(w + 28), checkSum: T.u32(w + 32),
      checkSumOffset: w + 32, subsystem: T.u16(w + 36), dllCharacteristics: T.u16(w + 38),
    });
    let p = w + 40;
    if (is64) {
      o.sizeOfStackReserve = T.u64(p); o.sizeOfStackCommit = T.u64(p + 8); o.sizeOfHeapReserve = T.u64(p + 16); o.sizeOfHeapCommit = T.u64(p + 24); p += 32;
    } else {
      o.sizeOfStackReserve = T.u32(p); o.sizeOfStackCommit = T.u32(p + 4); o.sizeOfHeapReserve = T.u32(p + 8); o.sizeOfHeapCommit = T.u32(p + 12); p += 16;
    }
    o.loaderFlags = T.u32(p); o.numberOfRvaAndSizes = T.u32(p + 4); p += 8;
    o.subsystemName = SUBSYSTEMS[o.subsystem] || `Unknown (${o.subsystem})`;
    o.dllCharacteristicsFlags = flagsOf(o.dllCharacteristics, DLL_CHARACTERISTICS);
    o.linkerVersion = `${o.majorLinkerVersion}.${o.minorLinkerVersion}`;
    o.osVersion = `${o.majorOperatingSystemVersion}.${o.minorOperatingSystemVersion}`;
    o.subsystemVersion = `${o.majorSubsystemVersion}.${o.minorSubsystemVersion}`;
    o.imageVersion = `${o.majorImageVersion}.${o.minorImageVersion}`;
    pe.optionalHeader = o;
    if (ohTruncated) warn(`The file ends inside the optional header (${bytes.length} bytes); missing fields are shown as 0.`, 'error');
    pe.isDriver = o.subsystem === 1 && !pe.isDll ? true : (o.dllCharacteristics & 0x2000) !== 0;

    // -- Data directories
    const n = Math.min(o.numberOfRvaAndSizes, 16);
    if (o.numberOfRvaAndSizes > 16) warn(`NumberOfRvaAndSizes is ${o.numberOfRvaAndSizes}; only 16 are defined (loader caps it).`);
    pe.dataDirectories = [];
    for (let i = 0; i < n; i++) {
      const at = p + i * 8;
      if (at + 8 > oh + ohSize + 8 && at + 8 > bytes.length) break;
      pe.dataDirectories.push({ index: i, name: DIRECTORY_NAMES[i], rva: T.u32(at), size: T.u32(at + 4), offset: at });
    }
    if (p + n * 8 > oh + ohSize && ohSize >= minOh) warn('Data directories extend past SizeOfOptionalHeader; the section table may be misread.');
  }
  pe.sectionTableOffset = oh + ohSize;

  // -- Section table
  pe.sections = [];
  const fileAlign = pe.optionalHeader ? pe.optionalHeader.fileAlignment : 0x200;
  const secOff = pe.sectionTableOffset ?? oh + ohSize;
  const nSec = pe.fileHeader.numberOfSections;
  if (nSec > MAX_SECTIONS) warn(`NumberOfSections is ${nSec}; the loader rejects more than ${MAX_SECTIONS}. Reading the first ${MAX_SECTIONS}.`, 'error');
  if (nSec === 0) warn('NumberOfSections is 0.', 'error');
  for (let i = 0; i < Math.min(nSec, MAX_SECTIONS); i++) {
    const at = secOff + i * 40;
    const ok = safe(`section ${i}`, () => {
      const rawName = r.bytes(at, 8);
      let end = 8; while (end > 0 && rawName[end - 1] === 0) end--;
      const name = latin1(rawName.subarray(0, end));
      const s = {
        index: i, offset: at, name, displayName: printable(name) || '(empty)',
        virtualSize: r.u32(at + 8), virtualAddress: r.u32(at + 12), sizeOfRawData: r.u32(at + 16), pointerToRawData: r.u32(at + 20),
        pointerToRelocations: r.u32(at + 24), pointerToLinenumbers: r.u32(at + 28), numberOfRelocations: r.u16(at + 32),
        numberOfLinenumbers: r.u16(at + 34), characteristics: r.u32(at + 36),
      };
      s.flags = flagsOf(s.characteristics, SECTION_FLAGS);
      s.executable = (s.characteristics & 0x20000000) !== 0; s.writable = (s.characteristics & 0x80000000) !== 0; s.readable = (s.characteristics & 0x40000000) !== 0;
      // The loader rounds raw pointers down to the file alignment (min 0x200).
      s.rawOffset = fileAlign >= 0x200 && s.pointerToRawData % 0x200 ? s.pointerToRawData - (s.pointerToRawData % 0x200) : s.pointerToRawData;
      s.rawEnd = Math.min(bytes.length, s.rawOffset + s.sizeOfRawData);
      s.rawAvailable = Math.max(0, s.rawEnd - s.rawOffset);
      s.truncated = s.sizeOfRawData > 0 && s.rawOffset + s.sizeOfRawData > bytes.length;
      s.virtualEnd = s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData);
      const data = r.clamped(s.rawOffset, s.sizeOfRawData);
      s.entropy = data.length ? entropy(data) : 0;
      s.md5 = opts.sectionHashes === false ? null : data.length ? md5(data) : null;
      pe.sections.push(s);
      return true;
    });
    if (!ok) break;
  }

  // -- RVA → file offset lookups (also re-attached on the UI thread after a worker hands back plain data)
  pe.sectionTableOffset = secOff;
  attachLookups(pe);
  const sizeOfHeaders = headersSize(pe);
  const off = (rva, what) => { const o = pe.rvaToOffset(rva); if (o === null) throw new PEError(`${what} RVA ${hex(rva)} does not map to file data`); return o; };
  const imageBase = pe.optionalHeader ? Number(pe.optionalHeader.imageBase) : 0;
  const vaToRva = (va) => Number(va) - imageBase;
  const ptrSize = pe.optionalHeader && pe.optionalHeader.is64 ? 8 : 4;
  const readPtr = (o) => (ptrSize === 8 ? r.u64(o) : r.u32(o));

  // -- Entry point
  if (pe.optionalHeader) {
    const ep = pe.optionalHeader.addressOfEntryPoint;
    const s = pe.sectionFor(ep);
    pe.entryPoint = { rva: ep, section: s ? s.displayName : null, sectionIndex: s ? s.index : null, offset: pe.rvaToOffset(ep) };
    pe.entryPoint.bytes = pe.entryPoint.offset !== null ? Array.from(r.clamped(pe.entryPoint.offset, 32)) : [];
  }

  // -- Directories
  pe.imports = safe('import directory', () => parseImports(r, pe, off)) || [];
  pe.delayImports = safe('delay import directory', () => parseDelayImports(r, pe, off, vaToRva, readPtr)) || [];
  pe.exports = safe('export directory', () => parseExports(r, pe, off));
  pe.resources = safe('resource directory', () => parseResources(r, pe, off, warn));
  pe.tls = safe('TLS directory', () => parseTls(r, pe, off, vaToRva, readPtr));
  pe.debug = safe('debug directory', () => parseDebug(r, pe, warn)) || [];
  pe.clr = safe('CLR header', () => parseClr(r, pe, off));
  pe.loadConfig = safe('load config', () => parseLoadConfig(r, pe, off, ptrSize));
  pe.relocations = safe('base relocations', () => parseRelocs(r, pe, off));
  pe.exceptions = safe('exception directory', () => { const d = pe.dir(3); return d ? { count: Math.floor(d.size / 12), size: d.size } : null; });
  pe.certificates = safe('security directory', () => parseCertificates(r, pe));
  pe.boundImports = safe('bound imports', () => parseBoundImports(r, pe));

  // -- Overlay (data after the last section; the Authenticode blob lives here)
  // Overlay starts after the last section's raw data, but never inside the headers themselves (tiny PEs claim SizeOfHeaders = 0).
  const headerBytes = Math.max(sizeOfHeaders, pe.sectionTableOffset + pe.sections.length * 40, nt + 24);
  let lastEnd = pe.sections.reduce((m, s) => Math.max(m, s.sizeOfRawData ? s.rawOffset + s.sizeOfRawData : 0), headerBytes);
  // Low-alignment images (SectionAlignment == FileAlignment < a page) are mapped flat, with SizeOfImage
  // rounded up to a whole page, so nothing inside that extent is overlay (corkami's tiny PEs rely on this).
  const ohx = pe.optionalHeader;
  if (ohx && ohx.sectionAlignment && ohx.sectionAlignment < 0x1000 && ohx.sectionAlignment === ohx.fileAlignment)
    lastEnd = Math.max(lastEnd, alignUp(ohx.sizeOfImage, 0x1000));
  if (bytes.length > lastEnd) {
    const certStart = pe.certificates ? pe.certificates.offset : null;
    const ov = { offset: lastEnd, size: bytes.length - lastEnd };
    ov.isCertificateOnly = certStart !== null && certStart <= lastEnd + 8 && pe.certificates.offset + pe.certificates.size >= bytes.length - 8;
    ov.certificateBytes = certStart !== null && certStart >= lastEnd ? Math.min(pe.certificates.size, bytes.length - certStart) : 0;
    ov.dataSize = ov.size - ov.certificateBytes;
    const data = r.clamped(lastEnd, ov.dataSize);
    ov.entropy = entropy(data);
    ov.head = Array.from(data.subarray(0, 16));
    ov.magic = sniff(data);
    pe.overlay = ov;
  } else pe.overlay = null;

  // -- Hashes (file hashes were computed up front, before anything could abort)
  pe.hashes.imphash = imphash(pe.imports);
  pe.hashes.richHash = pe.rich ? pe.rich.hash : null;
  if (pe.optionalHeader) {
    const computed = peChecksum(bytes, pe.optionalHeader.checkSumOffset);
    pe.checksum = { stored: pe.optionalHeader.checkSum, computed, matches: computed === pe.optionalHeader.checkSum };
  }

}

const headersSize = (pe) => (pe.optionalHeader ? pe.optionalHeader.sizeOfHeaders : (pe.sectionTableOffset || 0) + pe.sections.length * 40);

// Headers map 1:1 to the file; sections map by their raw pointer. Pure functions of the parsed data,
// so they can be re-attached to a report that crossed a worker boundary as plain JSON.
export function attachLookups(pe) {
  const sizeOfHeaders = headersSize(pe);
  const oh = pe.optionalHeader;
  const lowAlign = oh && oh.sectionAlignment && oh.sectionAlignment < 0x1000 && oh.sectionAlignment === oh.fileAlignment;
  pe.dir = (i) => (pe.dataDirectories && pe.dataDirectories[i] && pe.dataDirectories[i].rva ? pe.dataDirectories[i] : null);
  pe.sectionFor = (rva) => pe.sections.find((s) => rva >= s.virtualAddress && rva < s.virtualEnd && (s.virtualSize || s.sizeOfRawData)) || null;
  pe.rvaToOffset = (rva) => {
    if (!Number.isFinite(rva) || rva < 0) return null;
    if (lowAlign) return rva < pe.fileSize ? rva : null;
    const s = pe.sectionFor(rva);
    if (s) { const d = rva - s.virtualAddress; return d < s.sizeOfRawData ? s.rawOffset + d : null; }
    if (rva < sizeOfHeaders && rva < pe.fileSize) return rva;
    return null;
  };
  return pe;
}

// ---------- Rich header ----------
function parseRich(r, ntOffset) {
  const limit = Math.min(ntOffset, r.len - 8);
  let richAt = -1;
  for (let i = 0x40; i <= limit - 4; i += 4) if (r.u32(i) === 0x68636952 /* 'Rich' */) { richAt = i; break; }
  if (richAt < 0) return null;
  const key = r.u32(richAt + 4);
  let dansAt = -1;
  for (let i = richAt - 4; i >= 0x40; i -= 4) if ((r.u32(i) ^ key) === 0x536e6144 /* 'DanS' */) { dansAt = i; break; }
  if (dansAt < 0) return { present: true, valid: false, key, entries: [], note: 'Rich marker found but no DanS start.' };
  const entries = [];
  const clear = [];
  for (let i = dansAt; i < richAt; i += 4) clear.push((r.u32(i) ^ key) >>> 0);
  // clear[0] = DanS, clear[1..3] = padding, then (compid, count) pairs
  for (let i = 4; i + 1 < clear.length; i += 2) {
    const compid = clear[i], count = clear[i + 1];
    const productId = compid >>> 16, build = compid & 0xffff;
    entries.push({ productId, build, count, name: richProductName(productId), toolchain: richToolchain(productId) });
  }
  // Checksum: rotate-sum of the DOS header bytes (e_lfanew zeroed) + rotate of each compid by its count.
  let sum = dansAt;
  for (let i = 0; i < dansAt; i++) {
    if (i >= 0x3c && i < 0x40) continue;
    const b = r.u8(i);
    sum = (sum + (((b << (i % 32)) | (b >>> (32 - (i % 32)))) >>> 0)) >>> 0;
  }
  for (const e of entries) {
    const v = ((e.productId << 16) | e.build) >>> 0;
    const n = e.count % 32;
    sum = (sum + (n ? ((v << n) | (v >>> (32 - n))) >>> 0 : v)) >>> 0;
  }
  const clearBytes = new Uint8Array(clear.length * 4);
  const dv = new DataView(clearBytes.buffer);
  clear.forEach((v, i) => dv.setUint32(i * 4, v, true));
  const linker = entries.filter((e) => /Linker/.test(e.name || '')).map((e) => e.name + ' build ' + e.build);
  return { present: true, offset: dansAt, end: richAt + 8, key, checksum: sum, valid: sum === key, entries, hash: md5(clearBytes), linker };
}

// ---------- imports ----------
// Reads a thunk array. Garbage tables are the main way a corrupt file burns CPU, so besides the
// per-table cap we stop after a run of names that do not map anywhere (real tables never do that).
function readThunks(r, pe, off, thunkRva, ptrSize, dllName, budget = { left: MAX_TOTAL_THUNKS }) {
  const entries = [];
  let o = off(thunkRva, 'import thunk table');
  let badRun = 0;
  for (let i = 0; i < MAX_THUNKS && budget.left > 0; i++, o += ptrSize, budget.left--) {
    const v = ptrSize === 8 ? r.u64(o) : r.u32(o);
    if (v === 0 || v === 0n) break;
    const big = typeof v === 'bigint';
    const byOrdinal = big ? (v >> 63n) === 1n : ptrSize === 8 ? v >= 2 ** 63 : (v & 0x80000000) !== 0;
    if (byOrdinal) {
      const ordinal = Number(big ? v & 0xffffn : v & 0xffff);
      entries.push({ ordinal, name: null, display: ordinalName(dllName, ordinal), byOrdinal: true });
    } else {
      const rva = Number(v) & (ptrSize === 8 ? 0x7fffffff : 0x7fffffff);
      try {
        const no = off(rva, 'import name');
        const hint = r.u16(no);
        const name = r.cstr(no + 2, 1024);
        entries.push({ ordinal: null, hint, name, display: name, byOrdinal: false, rva });
        badRun = 0;
      } catch (e) {
        entries.push({ ordinal: null, hint: null, name: null, display: `(unreadable name at ${hex(rva)})`, byOrdinal: false, rva, bad: true });
        if (++badRun >= MAX_BAD_NAMES) throw new PEError(`${badRun} consecutive import names point outside the file; table abandoned`);
      }
    }
  }
  if (budget.left <= 0) throw new PEError(`more than ${MAX_TOTAL_THUNKS} imported functions in total; table abandoned`);
  return entries;
}
const looksLikeModuleName = (s) => typeof s === 'string' && s.length > 0 && s.length < 256 && /^[\x20-\x7e]+$/.test(s);

function parseImports(r, pe, off) {
  const d = pe.dir(1);
  if (!d) return [];
  const out = [];
  let o = off(d.rva, 'import directory');
  const ptrSize = pe.optionalHeader.is64 ? 8 : 4;
  const budget = { left: MAX_TOTAL_THUNKS };
  let badDlls = 0;
  for (let i = 0; i < MAX_IMPORT_DLLS; i++, o += 20) {
    const oft = r.u32(o), ts = r.u32(o + 4), fwd = r.u32(o + 8), nameRva = r.u32(o + 12), ft = r.u32(o + 16);
    if (oft === 0 && ts === 0 && fwd === 0 && nameRva === 0 && ft === 0) break;
    if (nameRva === 0 && ft === 0) break;
    const dll = { originalFirstThunk: oft, timeDateStamp: ts, forwarderChain: fwd, nameRva, firstThunk: ft, entries: [], bound: ts !== 0 };
    try { dll.name = r.cstr(off(nameRva, 'import DLL name'), 256); } catch (e) { dll.name = `(unreadable at ${hex(nameRva)})`; dll.bad = true; }
    if (!dll.bad && !looksLikeModuleName(dll.name)) { dll.bad = true; dll.name = printable(dll.name) || '(empty)'; }
    const thunk = oft || ft;
    if (thunk) {
      try { dll.entries = readThunks(r, pe, off, thunk, ptrSize, dll.name, budget); }
      catch (e) { dll.error = e.message; if (oft && ft && oft !== ft && budget.left > 0) { try { dll.entries = readThunks(r, pe, off, ft, ptrSize, dll.name, budget); dll.error = null; } catch (e2) { /* keep first error */ } } }
    }
    out.push(dll);
    // A descriptor whose name is garbage and whose thunks are unreadable is not a real import; a run of them means we walked off the table.
    if (dll.bad && (dll.error || !dll.entries.length)) { if (++badDlls >= MAX_BAD_DLLS) throw new PEError(`${badDlls} consecutive invalid import descriptors; directory abandoned at entry ${i}`); }
    else badDlls = 0;
    if (budget.left <= 0) throw new PEError(`more than ${MAX_TOTAL_THUNKS} imported functions in total; directory abandoned at entry ${i}`);
  }
  return out;
}

function parseDelayImports(r, pe, off, vaToRva, readPtr) {
  const d = pe.dir(13);
  if (!d) return [];
  const out = [];
  let o = off(d.rva, 'delay import directory');
  const ptrSize = pe.optionalHeader.is64 ? 8 : 4;
  const budget = { left: MAX_TOTAL_THUNKS };
  let badDlls = 0;
  for (let i = 0; i < MAX_IMPORT_DLLS; i++, o += 32) {
    const attrs = r.u32(o), nameRva0 = r.u32(o + 4), modRva = r.u32(o + 8), iat = r.u32(o + 12), int = r.u32(o + 16), bound = r.u32(o + 20), unload = r.u32(o + 24), ts = r.u32(o + 28);
    if (nameRva0 === 0 && int === 0 && iat === 0) break;
    const rvaBased = (attrs & 1) !== 0;
    const fix = (v) => (rvaBased || v === 0 ? v : vaToRva(v));
    const dll = { attributes: attrs, rvaBased, nameRva: fix(nameRva0), moduleHandleRva: fix(modRva), iatRva: fix(iat), intRva: fix(int), boundIatRva: fix(bound), unloadRva: fix(unload), timeDateStamp: ts, entries: [], delay: true };
    try { dll.name = r.cstr(off(dll.nameRva, 'delay import DLL name'), 256); } catch (e) { dll.name = `(unreadable at ${hex(dll.nameRva)})`; dll.bad = true; }
    if (!dll.bad && !looksLikeModuleName(dll.name)) { dll.bad = true; dll.name = printable(dll.name) || '(empty)'; }
    if (dll.intRva) { try { dll.entries = readThunks(r, pe, off, dll.intRva, ptrSize, dll.name, budget); } catch (e) { dll.error = e.message; } }
    out.push(dll);
    if (dll.bad && (dll.error || !dll.entries.length)) { if (++badDlls >= MAX_BAD_DLLS) throw new PEError(`${badDlls} consecutive invalid delay import descriptors; directory abandoned at entry ${i}`); }
    else badDlls = 0;
    if (budget.left <= 0) throw new PEError(`more than ${MAX_TOTAL_THUNKS} delay-imported functions in total; directory abandoned at entry ${i}`);
  }
  return out;
}

function parseBoundImports(r, pe) {
  const d = pe.dir(11);
  if (!d) return null;
  // Bound import descriptors live in the headers and use offsets relative to the directory start.
  const base = pe.rvaToOffset(d.rva);
  if (base === null) return null;
  const out = [];
  let o = base;
  for (let i = 0; i < 256; i++, o += 8) {
    const ts = r.u32(o), nameOff = r.u16(o + 4), nFwd = r.u16(o + 6);
    if (ts === 0 && nameOff === 0) break;
    out.push({ timeDateStamp: ts, timestamp: tsIso(ts), name: r.cstr(base + nameOff, 256), forwarderRefs: nFwd });
    o += nFwd * 8;
  }
  return out;
}

// ---------- exports ----------
function parseExports(r, pe, off) {
  const d = pe.dir(0);
  if (!d) return null;
  const o = off(d.rva, 'export directory');
  const e = {
    characteristics: r.u32(o), timeDateStamp: r.u32(o + 4), timestamp: tsIso(r.u32(o + 4)), majorVersion: r.u16(o + 8), minorVersion: r.u16(o + 10),
    nameRva: r.u32(o + 12), ordinalBase: r.u32(o + 16), numberOfFunctions: r.u32(o + 20), numberOfNames: r.u32(o + 24),
    addressOfFunctions: r.u32(o + 28), addressOfNames: r.u32(o + 32), addressOfNameOrdinals: r.u32(o + 36), functions: [],
  };
  try { e.name = r.cstr(off(e.nameRva, 'export name'), 256); } catch (err) { e.name = null; }
  const nFunc = Math.min(e.numberOfFunctions, MAX_EXPORTS), nNames = Math.min(e.numberOfNames, MAX_EXPORTS);
  if (e.numberOfFunctions > MAX_EXPORTS) e.note = `NumberOfFunctions ${e.numberOfFunctions} capped at ${MAX_EXPORTS}`;
  const funcs = off(e.addressOfFunctions, 'export address table');
  const names = new Map();
  if (nNames && e.addressOfNames && e.addressOfNameOrdinals) {
    const no = off(e.addressOfNames, 'export name table'), oo = off(e.addressOfNameOrdinals, 'export ordinal table');
    for (let i = 0; i < nNames; i++) {
      try {
        const nameRva = r.u32(no + i * 4), idx = r.u16(oo + i * 2);
        const name = r.cstr(off(nameRva, 'export name string'), 1024);
        if (!names.has(idx)) names.set(idx, []);
        names.get(idx).push(name);
      } catch (err) { e.namesError = err.message; break; }
    }
  }
  for (let i = 0; i < nFunc; i++) {
    const rva = r.u32(funcs + i * 4);
    if (rva === 0) continue;
    const f = { ordinal: e.ordinalBase + i, rva, names: names.get(i) || [], name: (names.get(i) || [null])[0] };
    if (rva >= d.rva && rva < d.rva + d.size) { try { f.forwarder = r.cstr(off(rva, 'forwarder'), 256); } catch (err) { f.forwarder = '(unreadable)'; } }
    else { const s = pe.sectionFor(rva); f.section = s ? s.displayName : null; }
    e.functions.push(f);
  }
  return e;
}

// ---------- resources ----------
function parseResources(r, pe, off, warn) {
  const d = pe.dir(2);
  if (!d) return null;
  const base = off(d.rva, 'resource directory');
  const res = { offset: base, rva: d.rva, size: d.size, types: [], count: 0, totalSize: 0, versionInfo: null, manifest: null, languages: new Set() };
  const seen = new Set();
  let budget = MAX_RESOURCE_ENTRIES;
  const readName = (field) => {
    if (field & 0x80000000) {
      const o = base + (field & 0x7fffffff);
      const n = r.u16(o);
      return { id: null, name: r.utf16(o + 2, Math.min(n, 256)) };
    }
    return { id: field, name: null };
  };
  const walk = (dirOff, depth, path) => {
    if (depth > MAX_RESOURCE_DEPTH || seen.has(dirOff)) { if (seen.has(dirOff)) warn('Resource directory loops back on itself.'); return []; }
    seen.add(dirOff);
    const named = r.u16(dirOff + 12), ids = r.u16(dirOff + 14);
    const n = named + ids;
    const out = [];
    for (let i = 0; i < n && budget > 0; i++, budget--) {
      const eo = dirOff + 16 + i * 8;
      const nameField = r.u32(eo), dataField = r.u32(eo + 4);
      const entry = readName(nameField);
      if (depth === 0) entry.typeName = entry.name || RESOURCE_TYPES[entry.id] || `#${entry.id}`;
      if (dataField & 0x80000000) {
        entry.children = walk(base + (dataField & 0x7fffffff), depth + 1, [...path, entry]);
      } else {
        const leafOff = base + dataField;
        const dataRva = r.u32(leafOff), size = r.u32(leafOff + 4), codePage = r.u32(leafOff + 8);
        const dataOff = pe.rvaToOffset(dataRva);
        const bytes = dataOff !== null ? r.clamped(dataOff, size) : new Uint8Array(0);
        Object.assign(entry, { rva: dataRva, size, codePage, offset: dataOff, lang: entry.id, available: bytes.length, entropy: bytes.length ? entropy(bytes) : 0, magic: sniff(bytes) });
        if (dataOff === null) entry.bad = true;
        res.count++; res.totalSize += size;
        if (entry.id !== null) res.languages.add(entry.id);
        const type = path[0];
        if (type && type.id === 16 && !res.versionInfo && bytes.length) res.versionInfo = safeCall(() => parseVersionInfo(bytes), warn, 'version info');
        if (type && type.id === 24 && !res.manifest && bytes.length) res.manifest = decodeText(bytes);
      }
      out.push(entry);
    }
    return out;
  };
  res.types = walk(base, 0, []);
  res.languages = [...res.languages];
  // Flatten for tables
  res.items = [];
  for (const t of res.types) for (const n of t.children || []) for (const l of n.children || []) res.items.push({ type: t.typeName, typeId: t.id, name: n.name !== null ? n.name : String(n.id), lang: l.id, rva: l.rva, size: l.size, offset: l.offset, entropy: l.entropy, magic: l.magic, bad: l.bad });
  return res;
}
const safeCall = (fn, warn, what) => { try { return fn(); } catch (e) { warn(`${what}: ${e.message}`); return null; } };

function decodeText(bytes) {
  try {
    if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder('utf-16le').decode(bytes.subarray(2));
    return new TextDecoder('utf-8').decode(bytes).replace(/^﻿/, '');
  } catch (e) { return latin1(bytes); }
}

// VS_VERSIONINFO: nested blocks of {wLength, wValueLength, wType, szKey, value, children}
export function parseVersionInfo(bytes) {
  const r = new Reader(bytes);
  const out = { fixed: null, strings: {}, translations: [] };
  const align4 = (n) => (n + 3) & ~3;
  const block = (o, end, depth, path) => {
    if (o + 6 > end || depth > 4) return end;
    const len = r.u16(o), valLen = r.u16(o + 2), type = r.u16(o + 4);
    if (len < 6) return end;
    const blockEnd = Math.min(end, o + len);
    const key = r.utf16z(o + 6, 128);
    let p = align4(o + 6 + (key.length + 1) * 2);
    const name = [...path, key];
    if (key === 'VS_VERSION_INFO' && valLen >= 52 && r.u32(p) === 0xfeef04bd) {
      const ver = (ms, ls) => `${ms >>> 16}.${ms & 0xffff}.${ls >>> 16}.${ls & 0xffff}`;
      out.fixed = {
        fileVersion: ver(r.u32(p + 8), r.u32(p + 12)), productVersion: ver(r.u32(p + 16), r.u32(p + 20)), fileFlagsMask: r.u32(p + 24), fileFlags: r.u32(p + 28),
        fileOS: r.u32(p + 32), fileType: r.u32(p + 36), fileSubtype: r.u32(p + 40),
      };
      out.fixed.fileTypeName = { 1: 'Application', 2: 'DLL', 3: 'Driver', 4: 'Font', 5: 'VXD', 7: 'Static library' }[out.fixed.fileType] || `0x${out.fixed.fileType.toString(16)}`;
      p = align4(p + valLen);
    } else if (path.length >= 2 && path[path.length - 2] === 'StringFileInfo') {
      // string value; wValueLength is in words, but some files store bytes or lie, so read until NUL within the block
      const v = r.utf16z(p, Math.max(0, Math.floor((blockEnd - p) / 2)));
      out.strings[key] = v;
      return blockEnd;
    } else if (path.length >= 1 && path[path.length - 1] === 'VarFileInfo' && key === 'Translation') {
      for (let q = p; q + 4 <= Math.min(blockEnd, p + valLen); q += 4) out.translations.push({ lang: r.u16(q), codePage: r.u16(q + 2) });
      return blockEnd;
    } else {
      p = align4(p + (type === 1 ? valLen * 2 : valLen));
    }
    while (p + 6 <= blockEnd) {
      const next = block(p, blockEnd, depth + 1, name);
      if (next <= p) break;
      p = align4(next);
    }
    return blockEnd;
  };
  block(0, bytes.length, 0, []);
  return out;
}

// ---------- TLS / debug / CLR / load config / relocs / certs ----------
function parseTls(r, pe, off, vaToRva, readPtr) {
  const d = pe.dir(9);
  if (!d) return null;
  const o = off(d.rva, 'TLS directory');
  const ps = pe.optionalHeader.is64 ? 8 : 4;
  const t = { startAddressOfRawData: readPtr(o), endAddressOfRawData: readPtr(o + ps), addressOfIndex: readPtr(o + 2 * ps), addressOfCallBacks: readPtr(o + 3 * ps),
    sizeOfZeroFill: r.u32(o + 4 * ps), characteristics: r.u32(o + 4 * ps + 4), callbacks: [] };
  if (t.addressOfCallBacks) {
    const rva = vaToRva(t.addressOfCallBacks);
    const co = pe.rvaToOffset(rva);
    if (co === null) t.callbacksNote = `callback array VA ${hex(t.addressOfCallBacks)} does not map to file data`;
    else for (let i = 0; i < MAX_TLS_CALLBACKS; i++) {
      const va = readPtr(co + i * ps);
      if (va === 0 || va === 0n) break;
      const crva = vaToRva(va);
      const s = pe.sectionFor(crva);
      t.callbacks.push({ va, rva: crva, section: s ? s.displayName : null });
    }
  }
  return t;
}

function parseDebug(r, pe, warn) {
  const d = pe.dir(6);
  if (!d) return [];
  const o = pe.rvaToOffset(d.rva);
  if (o === null) throw new PEError(`debug directory RVA ${hex(d.rva)} does not map to file data`);
  const n = Math.min(Math.floor(d.size / 28), MAX_DEBUG);
  const out = [];
  for (let i = 0; i < n; i++) {
    const e = o + i * 28;
    const entry = { characteristics: r.u32(e), timeDateStamp: r.u32(e + 4), timestamp: tsIso(r.u32(e + 4)), majorVersion: r.u16(e + 8), minorVersion: r.u16(e + 10),
      type: r.u32(e + 12), sizeOfData: r.u32(e + 16), addressOfRawData: r.u32(e + 20), pointerToRawData: r.u32(e + 24) };
    entry.typeName = DEBUG_TYPES[entry.type] || `Unknown (${entry.type})`;
    const dataOff = entry.pointerToRawData || pe.rvaToOffset(entry.addressOfRawData);
    if (dataOff && entry.sizeOfData) {
      try {
        if (entry.type === 2) {
          const sig = r.ascii(dataOff, 4);
          if (sig === 'RSDS') {
            const g = r.bytes(dataOff + 4, 16);
            const dv = new DataView(g.buffer, g.byteOffset, 16);
            const h = (n, w) => n.toString(16).padStart(w, '0');
            entry.codeView = { signature: sig, guid: `${h(dv.getUint32(0, true), 8)}-${h(dv.getUint16(4, true), 4)}-${h(dv.getUint16(6, true), 4)}-${h(g[8], 2)}${h(g[9], 2)}-${Array.from(g.subarray(10, 16), (b) => h(b, 2)).join('')}`,
              age: r.u32(dataOff + 20), pdb: r.cstr(dataOff + 24, Math.min(1024, entry.sizeOfData - 24)) };
          } else if (sig === 'NB10') {
            entry.codeView = { signature: sig, offset: r.u32(dataOff + 4), timestamp: r.u32(dataOff + 8), age: r.u32(dataOff + 12), pdb: r.cstr(dataOff + 16, Math.min(1024, entry.sizeOfData - 16)) };
          } else entry.codeView = { signature: printable(sig) };
        } else if (entry.type === 16) {
          entry.repro = { hash: Array.from(r.clamped(dataOff + 4, Math.min(32, entry.sizeOfData - 4)), (b) => b.toString(16).padStart(2, '0')).join('') };
        } else if (entry.type === 20) {
          entry.exDllCharacteristics = r.u32(dataOff);
          entry.cetCompat = (entry.exDllCharacteristics & 1) !== 0;
        } else if (entry.type === 13) {
          entry.pogo = { signature: r.u32(dataOff) === 0x4c544347 ? 'LTCG' : r.u32(dataOff) === 0x50474900 ? 'PGI' : r.u32(dataOff) === 0x50475500 ? 'PGU' : hex(r.u32(dataOff)) };
        }
      } catch (e) { entry.error = e.message; }
    }
    out.push(entry);
  }
  return out;
}

function parseClr(r, pe, off) {
  const d = pe.dir(14);
  if (!d) return null;
  const o = off(d.rva, 'CLR header');
  const c = { cb: r.u32(o), majorRuntimeVersion: r.u16(o + 4), minorRuntimeVersion: r.u16(o + 6), metaDataRva: r.u32(o + 8), metaDataSize: r.u32(o + 12), flags: r.u32(o + 16),
    entryPointToken: r.u32(o + 20), resourcesRva: r.u32(o + 24), resourcesSize: r.u32(o + 28), strongNameRva: r.u32(o + 32), strongNameSize: r.u32(o + 36) };
  c.flagNames = flagsOf(c.flags, [[0x1, 'ILONLY'], [0x2, '32BITREQUIRED'], [0x4, 'IL_LIBRARY'], [0x8, 'STRONGNAMESIGNED'], [0x10, 'NATIVE_ENTRYPOINT'], [0x10000, 'TRACKDEBUGDATA'], [0x20000, '32BITPREFERRED']]);
  try {
    const m = off(c.metaDataRva, 'CLR metadata');
    if (r.u32(m) === 0x424a5342) { const len = r.u32(m + 12); c.runtimeVersion = r.cstr(m + 16, Math.min(len, 64)); c.streams = r.u16(m + 16 + alignUp(len, 4) + 2); }
  } catch (e) { c.metadataError = e.message; }
  return c;
}

function parseLoadConfig(r, pe, off, ptrSize) {
  const d = pe.dir(10);
  if (!d) return null;
  const o = off(d.rva, 'load config');
  const size = r.u32(o);
  const lc = { size, timeDateStamp: r.u32(o + 4), majorVersion: r.u16(o + 8), minorVersion: r.u16(o + 10), globalFlagsClear: r.u32(o + 12), globalFlagsSet: r.u32(o + 16) };
  const is64 = ptrSize === 8;
  const cookieOff = is64 ? 88 : 60, guardFlagsOff = is64 ? 144 : 88, sehCountOff = is64 ? null : 68;
  const avail = Math.min(size, r.len - o);
  if (avail >= cookieOff + ptrSize) lc.securityCookie = is64 ? r.u64(o + cookieOff) : r.u32(o + cookieOff);
  if (sehCountOff !== null && avail >= sehCountOff + 4) lc.sehHandlerCount = r.u32(o + sehCountOff);
  if (avail >= guardFlagsOff + 4) {
    lc.guardFlags = r.u32(o + guardFlagsOff);
    lc.guardFlagNames = flagsOf(lc.guardFlags, [[0x100, 'CF_INSTRUMENTED'], [0x200, 'CFW_INSTRUMENTED'], [0x400, 'CF_FUNCTION_TABLE_PRESENT'], [0x800, 'SECURITY_COOKIE_UNUSED'],
      [0x1000, 'PROTECT_DELAYLOAD_IAT'], [0x2000, 'DELAYLOAD_IAT_IN_ITS_OWN_SECTION'], [0x4000, 'CF_EXPORT_SUPPRESSION_INFO_PRESENT'], [0x8000, 'CF_ENABLE_EXPORT_SUPPRESSION'],
      [0x10000, 'CF_LONGJUMP_TABLE_PRESENT'], [0x100000, 'RF_INSTRUMENTED'], [0x200000, 'RF_ENABLE'], [0x400000, 'RF_STRICT'], [0x800000, 'RETPOLINE_PRESENT'], [0x2000000, 'EH_CONTINUATION_TABLE_PRESENT'], [0x4000000, 'XFG_ENABLED']]);
  }
  return lc;
}

function parseRelocs(r, pe, off) {
  const d = pe.dir(5);
  if (!d) return null;
  const base = off(d.rva, 'base relocations');
  let o = base, blocks = 0, entries = 0;
  const end = Math.min(r.len, base + d.size);
  while (o + 8 <= end && blocks < MAX_RELOC_BLOCKS) {
    const pageRva = r.u32(o), size = r.u32(o + 4);
    if (size < 8) break;
    blocks++; entries += Math.floor((size - 8) / 2);
    o += size;
    if (pageRva === 0 && size === 0) break;
  }
  return { blocks, entries, size: d.size };
}

function parseCertificates(r, pe) {
  const d = pe.dir(4);
  if (!d) return null;
  // The security directory holds a FILE OFFSET, not an RVA.
  const c = { offset: d.rva, size: d.size, entries: [], commonNames: [] };
  if (d.rva + 8 > r.len) { c.error = `certificate table at file offset ${hex(d.rva)} is past end of file`; return c; }
  let o = d.rva;
  const end = Math.min(r.len, d.rva + d.size);
  for (let i = 0; i < MAX_CERTS && o + 8 <= end; i++) {
    const len = r.u32(o), rev = r.u16(o + 4), type = r.u16(o + 6);
    if (len < 8) break;
    const entry = { length: len, revision: rev, type, typeName: CERT_TYPES[type] || `Unknown (${hex(type)})`, truncated: o + len > r.len };
    const blob = r.clamped(o + 8, len - 8);
    entry.commonNames = x509CommonNames(blob);
    entry.signingTime = x509SigningTime(blob);
    entry.digestAlgorithm = /\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01/.test(latin1(blob.subarray(0, 64))) ? 'SHA-256' : /\x06\x05\x2b\x0e\x03\x02\x1a/.test(latin1(blob.subarray(0, 64))) ? 'SHA-1' : null;
    c.entries.push(entry);
    c.commonNames.push(...entry.commonNames);
    o += alignUp(len, 8);
  }
  c.commonNames = [...new Set(c.commonNames)];
  return c;
}
// Heuristic: pull CN= values (OID 2.5.4.3) out of the DER blob; order is roughly issuer, subject per certificate.
function x509CommonNames(blob) {
  const out = [];
  const pat = [0x06, 0x03, 0x55, 0x04, 0x03];
  for (let i = 0; i + 7 < blob.length && out.length < 64; i++) {
    let m = true;
    for (let j = 0; j < 5; j++) if (blob[i + j] !== pat[j]) { m = false; break; }
    if (!m) continue;
    const tag = blob[i + 5];
    let len = blob[i + 6], p = i + 7;
    if (len & 0x80) { const nb = len & 0x7f; if (nb > 2) continue; len = 0; for (let k = 0; k < nb; k++) len = (len << 8) | blob[p++]; }
    if (p + len > blob.length) continue;
    const raw = blob.subarray(p, p + len);
    let s = null;
    if (tag === 0x13 || tag === 0x0c || tag === 0x16) s = decodeText(raw);
    else if (tag === 0x1e) { s = ''; for (let k = 0; k + 1 < raw.length; k += 2) s += String.fromCharCode((raw[k] << 8) | raw[k + 1]); }
    if (s && !out.includes(s)) out.push(s);
  }
  return out;
}
// Heuristic: the first UTCTime/GeneralizedTime inside a signingTime attribute (OID 1.2.840.113549.1.9.5).
function x509SigningTime(blob) {
  const pat = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
  for (let i = 0; i + 16 < blob.length; i++) {
    let m = true;
    for (let j = 0; j < pat.length; j++) if (blob[i + j] !== pat[j]) { m = false; break; }
    if (!m) continue;
    for (let p = i + pat.length; p < Math.min(blob.length - 2, i + pat.length + 8); p++) {
      if (blob[p] === 0x17 || blob[p] === 0x18) {
        const len = blob[p + 1];
        const s = latin1(blob.subarray(p + 2, p + 2 + len));
        const mm = blob[p] === 0x17 ? s.match(/^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z?$/) : s.match(/^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/);
        if (!mm) return null;
        const year = blob[p] === 0x17 ? (Number(mm[1]) < 50 ? 2000 : 1900) + Number(mm[1]) : Number(mm[1]);
        return `${year}-${mm[2]}-${mm[3]}T${mm[4]}:${mm[5]}:${mm[6] || '00'}Z`;
      }
    }
  }
  return null;
}

// ---------- hashes & helpers ----------
export function imphash(imports) {
  if (!imports || !imports.length) return null;
  const parts = [];
  for (const dll of imports) {
    if (!dll.name) continue;
    let lib = dll.name.toLowerCase();
    const m = lib.match(/^(.*)\.(dll|sys|ocx)$/);
    if (m) lib = m[1];
    for (const e of dll.entries) {
      const fn = e.byOrdinal ? ordinalName(dll.name, e.ordinal) : e.name;
      if (!fn) continue;
      parts.push(`${lib}.${fn.toLowerCase()}`);
    }
  }
  return parts.length ? md5(parts.join(',')) : null;
}

export function peChecksum(bytes, checksumOffset) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const len = bytes.length;
  let sum = 0;
  const evenLen = len - (len % 2);
  for (let i = 0; i < evenLen; i += 2) {
    if (i === checksumOffset || i === checksumOffset + 2) continue;
    sum += dv.getUint16(i, true);
    if (sum > 0xffffffff) sum = (sum & 0xffffffff) + Math.floor(sum / 0x100000000);
  }
  if (len % 2) sum += bytes[len - 1];
  sum = (sum & 0xffff) + (sum >>> 16);
  sum = (sum & 0xffff) + (sum >>> 16);
  return (sum + len) >>> 0;
}

export function sniff(b) {
  if (!b || b.length < 4) return null;
  const s = latin1(b.subarray(0, 8));
  if (s.startsWith('MZ')) return 'PE/DOS executable';
  if (s.startsWith('PK\x03\x04')) return 'ZIP archive';
  if (s.startsWith('7z\xbc\xaf')) return '7-Zip archive';
  if (s.startsWith('Rar!')) return 'RAR archive';
  if (s.startsWith('%PDF')) return 'PDF';
  if (s.startsWith('\x89PNG')) return 'PNG image';
  if (s.startsWith('GIF8')) return 'GIF image';
  if (s.startsWith('\xff\xd8\xff')) return 'JPEG image';
  if (s.startsWith('BM')) return 'BMP image';
  if (s.startsWith('\xd0\xcf\x11\xe0')) return 'OLE compound document';
  if (s.startsWith('MSCF')) return 'Microsoft Cabinet';
  if (s.startsWith('\x1f\x8b')) return 'gzip';
  if (s.startsWith('<?xml') || s.startsWith('<assembly') || s.startsWith('\xef\xbb\xbf<')) return 'XML text';
  if (s.startsWith('\x30\x82')) return 'DER/ASN.1 (certificate?)';
  if (b[0] === 0 && b[1] === 0 && b[2] === 1 && b[3] === 0) return 'ICO';
  return null;
}

function kindOf(pe) {
  if (!pe.optionalHeader) return 'Unknown';
  if (pe.clr) return pe.isDll ? '.NET assembly (DLL)' : '.NET assembly (EXE)';
  if (pe.optionalHeader.subsystem === 1 && (pe.isDriver || /\.sys$/i.test(pe.exports?.name || ''))) return 'Kernel driver';
  if (pe.optionalHeader.subsystem >= 10 && pe.optionalHeader.subsystem <= 13) return 'EFI image';
  if (pe.isDll) return 'DLL';
  return 'Executable';
}

// JSON-safe copy of a report (drops functions, converts BigInts and Sets).
export function toJSON(pe) {
  return JSON.parse(JSON.stringify(pe, (k, v) => (typeof v === 'function' ? undefined : typeof v === 'bigint' ? '0x' + v.toString(16) : v instanceof Set ? [...v] : v)));
}
