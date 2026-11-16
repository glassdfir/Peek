// Triage layer: turns a parsed PE into findings an analyst can act on.
// Findings are observations with a severity, never a verdict. Severity:
//   high   - strong packer/injection/tampering signal, worth a close look
//   medium - unusual for a benign build
//   low    - mildly unusual or context-dependent
//   info   - worth knowing, normal on its own

import { hex } from './pe.js';

const PACKER_SECTIONS = {
  'UPX0': 'UPX', 'UPX1': 'UPX', 'UPX2': 'UPX', 'UPX!': 'UPX', '.UPX0': 'UPX', '.UPX1': 'UPX', '.aspack': 'ASPack', '.adata': 'ASPack', 'ASPack': 'ASPack',
  '.ASPack': 'ASPack', '.packed': 'RLPack', '.RLPack': 'RLPack', '.nsp0': 'NsPack', '.nsp1': 'NsPack', '.nsp2': 'NsPack', 'nsp0': 'NsPack', 'nsp1': 'NsPack',
  '.petite': 'Petite', '.themida': 'Themida', '.Themida': 'Themida', 'Themida': 'Themida', '.winapi': 'Themida/WinLicense', '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
  '.vmp2': 'VMProtect', '.vmp3': 'VMProtect', '.MPRESS1': 'MPRESS', '.MPRESS2': 'MPRESS', '.enigma1': 'Enigma', '.enigma2': 'Enigma', '.taggant': 'Taggant',
  '.boom': 'Boomerang', '.perplex': 'Perplex', '.yP': 'Y0da Protector', '.y0da': 'Y0da Protector', '.ccg': 'CCG', '.sforce3': 'StarForce', 'PEC2': 'PECompact',
  'PEC2TO': 'PECompact', 'PEC2MO': 'PECompact', 'PECompact2': 'PECompact', '.Upack': 'Upack', '.ByDll': 'Upack', 'kkrunchy': 'kkrunchy', '.neolit': 'NeoLite',
  '.neolite': 'NeoLite', '.mackt': 'ImpRec', '.MaskPE': 'MaskPE', '.spack': 'Simple Pack', '.pelock': 'PELock', '.WWP32': 'WWPack', '.WWPACK': 'WWPack', '.seau': 'SeauSFX',
  '.sedata': 'Shrinker', '.shrink1': 'Shrinker', '.shrink2': 'Shrinker', '.shrink3': 'Shrinker', '.svkp': 'SVKP', '.Tsuarch': 'TSULoader', '.TSustub': 'TSULoader',
  'DAStub': 'Dragon Armor', '.ecode': 'Built with EPL', '.edata': 'Export data (or EPL)', 'MEW': 'MEW', '.mnbvcx1': 'Unknown packer', '.mnbvcx2': 'Unknown packer',
  '.ndata': 'NSIS installer', '.nsp': 'NsPack', 'PEPACK!!': 'PE-Pack', 'pebundle': 'PEBundle', 'PEBundle': 'PEBundle', '.rmnet': 'Ramnit', '.gentee': 'Gentee installer',
  'Shared': 'Shared (unknown)', '.cdata': 'Possibly virus', '.imrsiv': 'Unknown packer', '.dyamarC': 'DYAMAR', '.dyamarD': 'DYAMAR', '.sdata': 'Unknown packer',
  '.vlizer': 'VProtect', '.zz0': 'Unknown packer', '.zz1': 'Unknown packer', 'BitArts': 'Crunch', 'hidden': 'Unknown packer', '.CRT': 'CRT', 'FSG!': 'FSG',
};
const STANDARD_SECTIONS = new Set(['.text', '.rdata', '.data', '.idata', '.edata', '.pdata', '.rsrc', '.reloc', '.bss', '.tls', '.CRT', '.gfids', '.00cfg',
  '.didat', '.textbss', '.xdata', '.debug', '.sxdata', '.rodata', '.fptable', '.voltbl', '.retplne', '.qtmetad', 'CODE', 'DATA', 'BSS', '.itext', '.tls', '_RDATA',
  '.giats', '.msvcjmc', '.eh_fram', '.buildid', '.drectve', '.detourc', '.detourd', '.mrdata', '.text$mn', '.rdata$r', '.orpc', '.vsdata', 'INIT', 'PAGE', 'PAGELK', 'NONPAGE', '.shared', '.ndata']);

// Imports worth calling out, grouped by what they enable. Matched case-insensitively, with A/W suffix stripped.
const NOTABLE = [
  ['Process injection', ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtCreateThreadEx', 'RtlCreateUserThread', 'NtUnmapViewOfSection',
    'NtMapViewOfSection', 'QueueUserAPC', 'NtQueueApcThread', 'SetThreadContext', 'NtSetContextThread', 'ResumeThread', 'NtWriteVirtualMemory', 'NtAllocateVirtualMemory', 'SetWindowsHookEx',
    'NtProtectVirtualMemory', 'VirtualProtectEx', 'CreateProcessInternal', 'ZwUnmapViewOfSection']],
  ['Dynamic API resolution', ['LoadLibrary', 'LoadLibraryEx', 'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress', 'GetModuleHandle', 'GetModuleHandleEx']],
  ['Anti-debug / anti-analysis', ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'OutputDebugString', 'NtSetInformationThread', 'GetTickCount',
    'GetTickCount64', 'QueryPerformanceCounter', 'NtQuerySystemInformation', 'FindWindow', 'BlockInput', 'NtYieldExecution', 'DebugActiveProcess', 'GetThreadContext']],
  ['Memory / execution', ['VirtualAlloc', 'VirtualProtect', 'HeapCreate', 'NtAllocateVirtualMemory', 'CreateThread', 'WinExec', 'ShellExecute', 'ShellExecuteEx', 'CreateProcess',
    'CreateProcessAsUser', 'CreateProcessWithLogon', 'CreateProcessWithToken', 'system', '_wsystem', 'RtlMoveMemory', 'CallWindowProc', 'EnumWindows', 'EnumSystemLocales', 'CreateFiber']],
  ['Networking', ['WSAStartup', 'socket', 'connect', 'send', 'recv', 'bind', 'listen', 'accept', 'gethostbyname', 'getaddrinfo', 'InternetOpen', 'InternetOpenUrl', 'InternetReadFile',
    'InternetConnect', 'HttpOpenRequest', 'HttpSendRequest', 'URLDownloadToFile', 'URLDownloadToCacheFile', 'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest', 'WinHttpReadData',
    'WinHttpOpenRequest', 'WNetAddConnection2', 'DnsQuery', 'DnsQuery_A', 'DnsQuery_W', 'WSASocket', 'WSAConnect', 'WSASend', 'WSARecv', 'InternetCrackUrl', 'FtpPutFile', 'FtpGetFile', 'IcmpSendEcho']],
  ['Persistence / registry / services', ['RegSetValueEx', 'RegCreateKeyEx', 'RegCreateKey', 'RegSetKeyValue', 'CreateService', 'StartService', 'ChangeServiceConfig', 'ChangeServiceConfig2',
    'OpenSCManager', 'CoCreateInstance', 'NetScheduleJobAdd', 'SetFileAttributes', 'CopyFile', 'MoveFile', 'MoveFileEx', 'CreateSymbolicLink', 'SHGetSpecialFolderPath', 'SHGetFolderPath']],
  ['Credentials / tokens', ['CredEnumerate', 'CredRead', 'CryptUnprotectData', 'LsaRetrievePrivateData', 'OpenProcessToken', 'AdjustTokenPrivileges', 'LookupPrivilegeValue',
    'DuplicateTokenEx', 'ImpersonateLoggedOnUser', 'LogonUser', 'SamIConnect', 'LsaOpenPolicy', 'NetUserAdd', 'NetLocalGroupAddMembers', 'SetTokenInformation', 'WNetEnumResource']],
  ['Cryptography', ['CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptDeriveKey', 'CryptImportKey', 'CryptHashData', 'CryptCreateHash', 'BCryptEncrypt',
    'BCryptDecrypt', 'BCryptGenRandom', 'BCryptOpenAlgorithmProvider', 'BCryptGenerateSymmetricKey', 'CryptGenRandom', 'CryptStringToBinary', 'CryptBinaryToString', 'CryptProtectData']],
  ['Keylogging / input capture', ['GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState', 'SetWindowsHookEx', 'RegisterRawInputDevices', 'GetRawInputData', 'MapVirtualKey', 'GetForegroundWindow',
    'GetWindowText', 'AttachThreadInput', 'GetClipboardData', 'SetClipboardViewer', 'BitBlt', 'GetDC', 'GetDIBits']],
  ['Enumeration / discovery', ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next', 'Module32First', 'Module32Next', 'Thread32First', 'EnumProcesses', 'EnumProcessModules',
    'GetComputerName', 'GetComputerNameEx', 'GetUserName', 'GetUserNameEx', 'NetUserEnum', 'NetShareEnum', 'NetServerEnum', 'GetAdaptersInfo', 'GetAdaptersAddresses', 'GetVolumeInformation',
    'GetSystemInfo', 'GetNativeSystemInfo', 'GetVersionEx', 'IsWow64Process', 'GetLogicalDrives', 'GetDriveType', 'FindFirstFile', 'FindNextFile', 'GetWindowsDirectory', 'GetSystemDirectory', 'LookupAccountName', 'GetLocaleInfo', 'GetUserDefaultUILanguage', 'GetSystemDefaultLangID', 'GetKeyboardLayoutList']],
  ['Files / self-modification', ['DeleteFile', 'WriteFile', 'CreateFile', 'SetFileTime', 'GetTempPath', 'GetTempFileName', 'GetModuleFileName', 'FindResource', 'LoadResource', 'LockResource',
    'SizeofResource', 'UpdateResource', 'BeginUpdateResource', 'NtSetInformationFile', 'DeviceIoControl', 'CreateFileMapping', 'MapViewOfFile', 'NtCreateSection']],
  ['Service / driver control', ['NtLoadDriver', 'ZwLoadDriver', 'CreateService', 'ControlService', 'DeleteService', 'OpenService']],
  ['Scripting / COM / WMI', ['CoInitializeSecurity', 'CoCreateInstance', 'CoGetObject', 'CoInitializeEx', 'VariantInit', 'SysAllocString', 'CLSIDFromProgID', 'CoCreateGuid']],
  ['Shell / UI', ['ShellExecute', 'ShellExecuteEx', 'SHGetSpecialFolderPath', 'ShowWindow', 'MessageBox', 'SetWindowLong', 'SetWindowLongPtr', 'SystemParametersInfo']],
];

const norm = (s) => s.replace(/(?:A|W|Ex|ExA|ExW)$/, '').toLowerCase();
const NOTABLE_INDEX = new Map();
for (const [group, apis] of NOTABLE) for (const api of apis) { const k = norm(api); if (!NOTABLE_INDEX.has(k)) NOTABLE_INDEX.set(k, []); NOTABLE_INDEX.get(k).push(group); }

export function analyze(pe, opts = {}) {
  const findings = [];
  const notable = [];
  let packerHint = null;
  const add = (severity, title, detail = '', where = null) => findings.push({ severity, title, detail, where });
  const now = (opts.now ?? Date.now()) / 1000;

  if (pe.errors.length) { for (const e of pe.errors) add('high', 'Not a loadable PE', e); }
  for (const w of pe.warnings) add(w.level === 'error' ? 'medium' : 'low', 'Parser warning', w.text);
  if (!pe.fileHeader) return finish();

  const fh = pe.fileHeader, oh = pe.optionalHeader;
  const repro = pe.debug.some((d) => d.type === 16);

  // --- timestamps
  if (fh.timeDateStamp === 0) add('medium', 'Compile timestamp is zero', 'The linker timestamp was cleared. Some toolchains do this on purpose (Delphi, Go without -buildid, some packers), but it is also done to hide build age.');
  else if (repro) add('info', 'Reproducible build', 'A REPRO debug entry is present; the file header timestamp is a hash of the build, not a date, so do not read it as compile time.');
  else if (fh.timeDateStamp > now + 86400) add('medium', 'Compile timestamp is in the future', `${fh.timestamp} is after now. Timestomped or deliberately fake.`);
  else if (fh.timeDateStamp < 788918400) add('low', 'Compile timestamp predates 1995', `${fh.timestamp} is implausibly old for a PE; probably forged.`);
  for (const d of pe.debug) if (d.timeDateStamp && !repro && fh.timeDateStamp && d.timeDateStamp !== fh.timeDateStamp) {
    add('low', 'Debug directory timestamp differs from file header', `Debug entry (${d.typeName}) says ${d.timestamp}, header says ${fh.timestamp}. One of them was edited, or the file was re-linked.`); break;
  }
  if (pe.exports && pe.exports.timeDateStamp && pe.exports.timeDateStamp !== 0xffffffff && !repro && fh.timeDateStamp && pe.exports.timeDateStamp !== fh.timeDateStamp)
    add('low', 'Export directory timestamp differs from file header', `Export table says ${pe.exports.timestamp}, header says ${fh.timestamp}.`);
  if (pe.certificates && pe.certificates.entries[0] && pe.certificates.entries[0].signingTime && fh.timeDateStamp && !repro) {
    const st = Date.parse(pe.certificates.entries[0].signingTime) / 1000;
    if (st < fh.timeDateStamp - 3600) add('medium', 'Signed before it was compiled', `Signature time ${pe.certificates.entries[0].signingTime} precedes the compile time ${fh.timestamp}.`);
  }

  if (!oh) { add('high', 'No optional header', 'The file cannot be loaded as an image.'); return finish(); }

  // --- header sanity
  if (oh.magic !== 0x10b && oh.magic !== 0x20b) add('high', 'Invalid optional header magic', `Magic ${hex(oh.magic)} is not PE32 or PE32+.`);
  const want64 = [0x8664, 0xaa64, 0x200, 0xa641, 0xa64e, 0x5064, 0x6264].includes(fh.machine);
  if (oh.is64 !== want64 && fh.machine !== 0) add('medium', 'Machine type does not match PE32/PE32+ format', `${fh.machineName} with a ${oh.format} optional header.`);
  if (fh.numberOfSections === 0) add('high', 'No sections', 'An image with no sections cannot run normally.');
  if (fh.numberOfSections > 20) add('low', 'Many sections', `${fh.numberOfSections} sections is unusual for a compiler-built image.`);
  if (oh.sizeOfHeaders === 0 || oh.sizeOfHeaders > 0x10000) add('medium', 'Odd SizeOfHeaders', hex(oh.sizeOfHeaders));
  const first = pe.sections.find((s) => s.sizeOfRawData);
  if (first && first.rawOffset < oh.sizeOfHeaders) add('medium', 'First section raw data overlaps the headers', `Section ${first.displayName} starts at ${hex(first.rawOffset)} but SizeOfHeaders is ${hex(oh.sizeOfHeaders)}.`);
  const lastVirt = pe.sections.reduce((m, s) => Math.max(m, s.virtualAddress + s.virtualSize), oh.sizeOfHeaders);
  const align = (n) => (oh.sectionAlignment ? Math.ceil(n / oh.sectionAlignment) * oh.sectionAlignment : n);
  if (pe.sections.length && align(lastVirt) !== align(oh.sizeOfImage)) add('low', 'SizeOfImage does not match the section table', `Header says ${hex(oh.sizeOfImage)}, sections end at ${hex(align(lastVirt))}.`);
  if (oh.sectionAlignment && oh.fileAlignment && oh.sectionAlignment < oh.fileAlignment) add('medium', 'SectionAlignment is smaller than FileAlignment', 'Not a layout a normal linker produces.');
  if (oh.fileAlignment && (oh.fileAlignment & (oh.fileAlignment - 1))) add('low', 'FileAlignment is not a power of two', hex(oh.fileAlignment));
  if (pe.checksum && pe.checksum.stored && !pe.checksum.matches) add(pe.isDriver || pe.certificates ? 'medium' : 'low', 'PE checksum does not match', `Stored ${hex(pe.checksum.stored)}, computed ${hex(pe.checksum.computed)}. The file was modified after linking, or the checksum was never updated. ${pe.certificates ? 'Signed files normally carry a valid checksum.' : ''}`);
  if (pe.checksum && !pe.checksum.stored && (pe.isDriver || pe.certificates)) add('low', 'PE checksum is zero', 'Drivers and signed files normally set one.');
  if (!oh.dllCharacteristicsFlags.includes('NX_COMPAT')) add('info', 'DEP (NX) not opted in', 'NX_COMPAT is not set. Common for old or hand-built binaries.');
  if (!oh.dllCharacteristicsFlags.includes('DYNAMIC_BASE')) add('info', 'ASLR not opted in', 'DYNAMIC_BASE is not set, so the image loads at its preferred base.');
  else if (fh.characteristicsFlags.includes('RELOCS_STRIPPED') || !pe.dir(5)) add('low', 'ASLR requested but relocations are missing', 'DYNAMIC_BASE is set but there is no relocation table, so the image cannot actually be rebased.');
  if (oh.is64 && !oh.dllCharacteristicsFlags.includes('HIGH_ENTROPY_VA') && oh.dllCharacteristicsFlags.includes('DYNAMIC_BASE')) add('info', 'No high-entropy ASLR', 'HIGH_ENTROPY_VA is not set on a 64-bit image.');
  if (oh.dllCharacteristicsFlags.includes('FORCE_INTEGRITY') && !pe.certificates) add('medium', 'FORCE_INTEGRITY set on an unsigned file', 'The loader will refuse this image unless it is signed.');
  if (oh.loaderFlags) add('low', 'LoaderFlags is non-zero', `${hex(oh.loaderFlags)}; the field is reserved and should be 0.`);
  if (oh.win32VersionValue) add('low', 'Win32VersionValue is non-zero', `${hex(oh.win32VersionValue)}; reserved, and sometimes used to confuse the loader's version checks.`);

  // --- entry point
  const ep = pe.entryPoint;
  // Effective end of the headers: SizeOfHeaders, or where the first section's data starts when the field is 0 (tiny PEs).
  const firstRaw = pe.sections.filter((s) => s.sizeOfRawData).map((s) => s.rawOffset);
  const headerEnd = oh.sizeOfHeaders || (firstRaw.length ? Math.min(...firstRaw) : pe.fileSize);
  if (ep) {
    if (ep.rva === 0 && !pe.isDll) add('medium', 'Entry point is zero', 'An EXE with no entry point will not run as a process (unless it is a .NET or resource-only image).');
    else if (ep.rva && !ep.section && ep.rva < headerEnd) add('medium', 'Entry point is inside the headers', `${hex(ep.rva)} is in the header area (which ends at ${hex(headerEnd)}). Code there runs on Windows 7 and earlier; Windows 8+ refuses such images. A proof-of-concept or packer trick.`);
    else if (ep.rva && !ep.section) add('high', 'Entry point is outside every section', `${hex(ep.rva)} is not inside any section. The image will not start normally; this is a classic corruption or packer trick.`);
    else if (ep.rva) {
      const s = pe.sections[ep.sectionIndex];
      if (!s.executable) add('high', 'Entry point is in a non-executable section', `${s.displayName} is not marked MEM_EXECUTE. Will fault under DEP, or the flags were tampered.`);
      if (s.writable) add('high', 'Entry point is in a writable section', `${s.displayName} is writable and executable. Typical of a packer stub or self-modifying code.`);
      if (ep.offset === null) add('high', 'Entry point has no file data', 'The entry RVA lies in the virtual-only part of its section; code must be written there at runtime (packer/dropper).');
      if (pe.sections.length > 1 && ep.sectionIndex === pe.sections.length - 1 && !/^\.text$|^CODE$/.test(s.name)) add('medium', 'Entry point is in the last section', `${s.displayName}; packers often append their unpacking stub as the final section.`);
      if (!/^(\.text|CODE|\.itext|\.textbss|INIT|\.code|\.text\$mn|__TEXT|\.init)$/.test(s.name) && !pe.clr) add('low', 'Entry point is not in .text', `Entry section is ${s.displayName}.`);
      if (ep.bytes.length && ep.bytes.every((b) => b === 0)) add('high', 'Entry point bytes are all zero', 'The code at the entry point is empty in the file.');
    }
  }

  // --- sections
  const seenNames = new Map();
  for (const s of pe.sections) {
    const w = s.displayName;
    const packer = PACKER_SECTIONS[s.name];
    if (packer) { add('high', `Packer section name: ${w}`, `Section name associated with ${packer}.`, w); packerHint = packerHint || packer; }
    else if (!STANDARD_SECTIONS.has(s.name) && s.executable) add('low', `Non-standard executable section ${w}`, 'Compiler-built images put code in .text; a custom name on an executable section deserves a look.', w);
    if (!s.name) add('medium', 'Section with empty name', `Section ${s.index} has no name.`, w);
    else if (/[^\x20-\x7e]/.test(s.name)) add('medium', `Section name has non-printable bytes: ${w}`, 'Linkers emit ASCII names.', w);
    if (seenNames.has(s.name) && s.name) add('low', `Duplicate section name ${w}`, 'Two sections share a name (legal, but unusual outside packers and some installers).', w);
    seenNames.set(s.name, true);
    if (s.executable && s.writable) add(s.name === '.text' ? 'high' : 'medium', `Section ${w} is writable and executable`, 'W+X memory is what packers, self-modifying code and some JITs need; compilers do not emit it.', w);
    if (s.entropy > 7.2 && s.rawAvailable > 1024) add(s.executable ? 'high' : s.name === '.rsrc' ? 'low' : 'medium', `High entropy in ${w} (${s.entropy.toFixed(2)})`, `${s.executable ? 'Executable' : 'Data'} section looks compressed or encrypted. Plain code is usually 5.5–6.8.`, w);
    if (s.executable && s.entropy > 0 && s.entropy < 1.5 && s.rawAvailable > 1024) add('low', `Very low entropy in executable section ${w} (${s.entropy.toFixed(2)})`, 'Mostly padding; code is normally denser.', w);
    if (s.sizeOfRawData === 0 && s.virtualSize > 0 && s.executable) add('high', `Executable section ${w} has no data on disk`, `${hex(s.virtualSize)} bytes of executable memory with nothing in the file: it gets filled at runtime (unpacking).`, w);
    else if (s.sizeOfRawData === 0 && s.virtualSize > 0x100000 && !/bss/i.test(s.name)) add('low', `Large virtual-only section ${w}`, `${hex(s.virtualSize)} bytes reserved with no file data.`, w);
    if (s.truncated) add('high', `Section ${w} is truncated`, `Raw data runs to ${hex(s.rawOffset + s.sizeOfRawData)} but the file is ${hex(pe.fileSize)} bytes. Truncated download or a size field edited to confuse tools.`, w);
    if (s.virtualSize && s.sizeOfRawData > s.virtualSize * 4 && s.sizeOfRawData > 0x10000 && !/rsrc/.test(s.name)) add('medium', `Section ${w} has far more raw data than virtual size`, `${hex(s.sizeOfRawData)} on disk vs ${hex(s.virtualSize)} in memory. Data hidden past the mapped size.`, w);
    if (oh.fileAlignment && s.pointerToRawData % oh.fileAlignment) add('low', `Section ${w} raw pointer is not file-aligned`, `${hex(s.pointerToRawData)} is not a multiple of ${hex(oh.fileAlignment)}; the loader rounds it down.`, w);
    if (oh.sectionAlignment && s.virtualAddress % oh.sectionAlignment) add('medium', `Section ${w} virtual address is not section-aligned`, `${hex(s.virtualAddress)} is not a multiple of ${hex(oh.sectionAlignment)}.`, w);
  }
  for (let i = 1; i < pe.sections.length; i++) {
    const a = pe.sections[i - 1], b = pe.sections[i];
    if (b.virtualAddress < a.virtualAddress + a.virtualSize && a.virtualSize) add('medium', `Sections ${a.displayName} and ${b.displayName} overlap in memory`, 'Section virtual ranges should be ordered and disjoint.');
    if (b.virtualAddress < a.virtualAddress) add('medium', 'Sections are not in ascending address order', `${b.displayName} comes after ${a.displayName} but has a lower RVA.`);
    if (a.sizeOfRawData && b.sizeOfRawData && b.rawOffset < a.rawOffset + a.sizeOfRawData && b.rawOffset >= a.rawOffset) add('low', `Sections ${a.displayName} and ${b.displayName} overlap on disk`, 'Raw data ranges share bytes.');
  }

  // --- imports
  const allImports = [...pe.imports, ...pe.delayImports];
  const apiNames = [];
  for (const dll of pe.imports) for (const e of dll.entries) apiNames.push(e.display);
  const lower = new Set(apiNames.map((n) => norm(n)));
  if (!pe.dir(1) && !pe.clr) add(pe.isDriver ? 'low' : 'high', 'No import table', 'Almost every real program imports something. None at all means a packer, a shellcode wrapper, a driver, or manual API resolution.');
  else if (pe.imports.length && apiNames.length <= 6 && !pe.clr) {
    const dyn = lower.has('loadlibrary') && lower.has('getprocaddress');
    add(dyn ? 'high' : 'medium', `Only ${apiNames.length} import${apiNames.length === 1 ? '' : 's'}`, dyn ? 'Just enough to resolve everything else at runtime (LoadLibrary + GetProcAddress): the hallmark of a packed or obfuscated binary.' : 'Very small import table; code either does little or resolves APIs by hand.');
  }
  for (const dll of allImports) {
    if (dll.bad || /[^\x20-\x7e]/.test(dll.name || '')) add('medium', 'Import DLL name is unreadable', dll.name);
    else if (dll.name && !/\.(dll|exe|sys|drv|ocx|cpl)$/i.test(dll.name) && !/^api-ms-|^ext-ms-/i.test(dll.name)) add('low', `Import from unusual module name ${dll.name}`, 'Not a .dll/.exe/.sys name.');
    if (dll.error) add('low', `Import table for ${dll.name} is damaged`, dll.error);
    if (dll.name && /^(ntdll|ntoskrnl)\.dll$/i.test(dll.name) && !pe.isDriver && dll.entries.some((e) => /^(Nt|Zw)/.test(e.display))) add('low', 'Direct native (Nt*/Zw*) calls', `Imports ${dll.entries.filter((e) => /^(Nt|Zw)/.test(e.display)).map((e) => e.display).slice(0, 8).join(', ')}${dll.entries.length > 8 ? ', …' : ''} from ${dll.name}. Legitimate in system components and some runtimes; otherwise it is bypassing the Win32 layer.`);
    const bad = dll.entries.filter((e) => e.bad).length;
    if (bad) add('low', `${bad} unreadable import name${bad > 1 ? 's' : ''} in ${dll.name}`, 'Name RVAs point outside the file.');
  }
  const groups = new Map();
  for (const dll of allImports) for (const e of dll.entries) {
    const g = NOTABLE_INDEX.get(norm(e.display));
    if (!g) continue;
    for (const group of g) { if (!groups.has(group)) groups.set(group, new Set()); groups.get(group).add(`${e.display}${dll.delay ? ' (delay)' : ''}`); }
  }
  for (const [group, apis] of groups) notable.push({ group, apis: [...apis].sort() });
  notable.sort((a, b) => b.apis.length - a.apis.length);
  const inj = groups.get('Process injection');
  if (inj && [...inj].filter((a) => /WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext|NtUnmapViewOfSection|NtMapViewOfSection/i.test(a)).length >= 2)
    add('medium', 'Imports a process-injection API set', [...inj].join(', '));
  if (groups.get('Keylogging / input capture') && [...groups.get('Keylogging / input capture')].some((a) => /GetAsyncKeyState|SetWindowsHookEx|GetRawInputData/i.test(a)))
    add('low', 'Imports keyboard-capture APIs', [...groups.get('Keylogging / input capture')].join(', '));

  // --- exports
  if (pe.exports) {
    if (!pe.isDll && pe.exports.functions.length) add('info', 'EXE exports functions', `${pe.exports.functions.length} exports on an executable (plugins and some runtimes do this).`);
    const fwd = pe.exports.functions.filter((f) => f.forwarder);
    if (fwd.length && fwd.length === pe.exports.functions.length && pe.exports.functions.length > 3) add('medium', 'All exports are forwarders', 'Every export forwards elsewhere: proxy/side-loading DLL pattern.');
    if (pe.exports.name && opts.fileName && pe.exports.name.toLowerCase() !== opts.fileName.toLowerCase() && !pe.exports.name.startsWith('(')) add('low', 'Export name differs from file name', `Export table says ${pe.exports.name}, file is ${opts.fileName}. Renamed since linking (common and harmless for copies, notable for DLL side-loading).`);
    const sus = pe.exports.functions.filter((f) => f.name && /^(DllRegisterServer|DllInstall|ServiceMain|CPlApplet|PlugIn|DllGetClassObject)$/i.test(f.name)).map((f) => f.name);
    if (sus.length) add('info', 'Exports a known execution entry', `${sus.join(', ')}: can be launched via regsvr32, rundll32, services or control.exe.`);
  }
  const vi = pe.resources && pe.resources.versionInfo;
  if (vi && vi.strings && vi.strings.OriginalFilename && opts.fileName && vi.strings.OriginalFilename.toLowerCase() !== opts.fileName.toLowerCase())
    add('low', 'OriginalFilename differs from file name', `Version resource says ${vi.strings.OriginalFilename}, file is ${opts.fileName}.`);
  if (vi && vi.strings && /microsoft/i.test(vi.strings.CompanyName || '') && !pe.certificates) add('medium', 'Claims to be Microsoft but is unsigned', `CompanyName "${vi.strings.CompanyName}" with no Authenticode signature. Microsoft ships signed binaries.`);
  if (pe.dir(2) && !vi && !pe.isDriver && !pe.clr && pe.resources && pe.resources.count) add('info', 'No version information resource', 'Most shipped software has one; many malware builds and hand-rolled tools do not.');
  if (!pe.dir(2) && !pe.isDriver && !pe.clr) add('info', 'No resources at all', 'No icon, version info or manifest.');

  // --- resources
  if (pe.resources) {
    for (const it of pe.resources.items) {
      if (it.magic === 'PE/DOS executable') add('high', `Embedded executable in resource ${it.type}/${it.name}`, `${hex(it.size)} bytes starting with MZ: a dropped payload or installer stub.`);
      else if ((it.magic === 'ZIP archive' || it.magic === '7-Zip archive' || it.magic === 'RAR archive' || it.magic === 'Microsoft Cabinet') && it.size > 4096) add('low', `Embedded ${it.magic} in resource ${it.type}/${it.name}`, `${hex(it.size)} bytes.`);
      else if (it.entropy > 7.5 && it.size > 8192 && !/ICON|PNG|BITMAP|CURSOR/.test(it.type)) add('medium', `High-entropy blob in resource ${it.type}/${it.name}`, `${hex(it.size)} bytes at entropy ${it.entropy.toFixed(2)}: encrypted or compressed payload.`);
      if (it.bad) add('low', `Resource ${it.type}/${it.name} points outside the file`, `RVA ${hex(it.rva)}.`);
    }
    if (pe.resources.manifest) {
      const m = pe.resources.manifest;
      const lvl = m.match(/requestedExecutionLevel[^>]*level\s*=\s*["']([^"']+)/i);
      if (lvl && /requireAdministrator/i.test(lvl[1])) add('info', 'Manifest requests administrator', 'requestedExecutionLevel=requireAdministrator: UAC prompt on launch.');
      if (/autoElevate>\s*true/i.test(m)) add('medium', 'Manifest sets autoElevate', 'Only Windows-signed binaries get silent elevation; this is a UAC-bypass marker on anything else.');
      if (/uiAccess\s*=\s*["']true/i.test(m)) add('low', 'Manifest requests uiAccess', 'Lets the process drive the UI of higher-integrity windows.');
    }
  }

  // --- TLS, debug, CLR, load config
  if (pe.tls && pe.tls.callbacks.length) add('medium', `${pe.tls.callbacks.length} TLS callback${pe.tls.callbacks.length > 1 ? 's' : ''}`, 'TLS callbacks run before the entry point, so they are a favourite spot for anti-debug and unpacking code. Some compilers (Rust, Go, MSVC with thread_local) emit one legitimately.');
  if (pe.tls && pe.tls.callbacksNote) add('low', 'TLS callback table unreadable', pe.tls.callbacksNote);
  for (const d of pe.debug) {
    if (d.codeView && d.codeView.pdb) {
      const p = d.codeView.pdb;
      if (/\\(users|home)\\[^\\]+\\/i.test(p)) add('info', 'PDB path reveals a user profile', p);
      if (/(?:^|\\)(?:[a-z0-9]{32,}|[0-9a-f]{8,})\.pdb$/i.test(p) || !/\.pdb$/i.test(p)) add('low', 'Unusual PDB path', p);
      if (/\b(payload|inject|hook|bypass|stealer|keylog|crypt|loader|dropper|shellcode|rat\b|bot\b|miner|ransom|evil|hack|backdoor|exploit|bind|beacon)/i.test(p)) add('medium', 'PDB path contains a suggestive word', p);
    }
    if (d.error) add('low', `Debug entry ${d.typeName} unreadable`, d.error);
  }
  if (pe.clr) {
    add('info', '.NET assembly', `CLR runtime ${pe.clr.runtimeVersion || `${pe.clr.majorRuntimeVersion}.${pe.clr.minorRuntimeVersion}`}; flags ${pe.clr.flagNames.join(', ') || 'none'}. Use a .NET decompiler for the real logic; this viewer only sees the PE wrapper.`);
    if (pe.clr.flagNames.includes('NATIVE_ENTRYPOINT')) add('medium', '.NET assembly with a native entry point', 'Mixed-mode or tampered: native code runs before the CLR.');
  }
  if (pe.loadConfig && pe.loadConfig.guardFlagNames) {
    if (!pe.loadConfig.guardFlagNames.includes('CF_INSTRUMENTED') && oh.dllCharacteristicsFlags.includes('GUARD_CF')) add('low', 'GUARD_CF flag set but load config says CFG is not instrumented', '');
  }
  if (pe.relocations && pe.relocations.blocks === 0 && pe.dir(5)) add('low', 'Empty relocation directory', '');

  // --- signature
  if (pe.certificates) {
    const c = pe.certificates;
    if (c.error) add('medium', 'Certificate table is unreadable', c.error);
    else {
      const cn = c.commonNames.filter((n) => !/\b(CA|Authority|PCA|Root|Time[- ]?Stamp|Timestamp|TSA)\b/i.test(n));
      add('info', 'Authenticode signature present', `${c.entries.length} certificate blob${c.entries.length > 1 ? 's' : ''}${cn.length ? '; names seen: ' + cn.slice(0, 4).join(', ') : ''}${c.entries[0] && c.entries[0].digestAlgorithm ? ' (' + c.entries[0].digestAlgorithm + ')' : ''}. Presence only: this viewer does not validate the chain or the hash.`);
      if (c.entries.some((e) => e.truncated)) add('medium', 'Certificate blob is truncated', 'The security directory extends past the end of the file.');
      if (c.entries[0] && c.entries[0].digestAlgorithm === 'SHA-1') add('low', 'SHA-1 Authenticode digest', 'Modern Windows no longer trusts SHA-1 signatures for new code.');
    }
  } else if (!pe.isDriver && !pe.clr && vi && vi.strings && vi.strings.CompanyName) add('info', 'Unsigned', 'No Authenticode signature. Normal for in-house, open-source and older software.');
  else if (pe.isDriver && !pe.certificates) add('medium', 'Unsigned driver', 'Modern Windows will not load it without test-signing mode or an exploit.');

  // --- overlay
  if (pe.overlay && pe.overlay.dataSize > 0) {
    const o = pe.overlay;
    const pct = o.dataSize / pe.fileSize;
    const what = o.magic ? ` Starts like a ${o.magic}.` : '';
    if (o.magic === 'PE/DOS executable') add('high', 'Overlay contains an executable', `${hex(o.dataSize)} bytes after the last section start with MZ.`);
    else if (pct > 0.5) add(o.entropy > 7.2 ? 'high' : 'medium', `Overlay is ${Math.round(pct * 100)}% of the file`, `${o.dataSize} bytes after the last section (entropy ${o.entropy.toFixed(2)}).${what} Installers (NSIS, Inno, self-extractors) do this legitimately; so do droppers.`);
    else if (o.dataSize > 1024) add(o.entropy > 7.2 ? 'medium' : 'low', 'Data after the last section (overlay)', `${o.dataSize} bytes, entropy ${o.entropy.toFixed(2)}.${what} Not mapped by the loader; the program must read its own file to use it.`);
  }

  return finish();

  function finish() {
    const order = { high: 0, medium: 1, low: 2, info: 3 };
    findings.sort((a, b) => order[a.severity] - order[b.severity]);
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) counts[f.severity]++;
    return { findings, notableImports: notable, counts, packerHint, summary: summarize(pe, packerHint) };
  }
}

function summarize(pe, packerHint) {
  const fh = pe.fileHeader, oh = pe.optionalHeader;
  if (!fh) return null;
  const vi = pe.resources && pe.resources.versionInfo;
  const compiler = guessCompiler(pe);
  return {
    kind: pe.kind, machine: fh.machineName, format: oh ? oh.format : null, subsystem: oh ? oh.subsystemName : null,
    compiled: fh.timestamp && pe.debug.some((d) => d.type === 16) ? `${fh.timestamp} (reproducible-build hash, not a date)` : fh.timestamp,
    linker: oh ? oh.linkerVersion : null, compiler, packer: packerHint,
    description: vi && vi.strings ? vi.strings.FileDescription || null : null, company: vi && vi.strings ? vi.strings.CompanyName || null : null,
    originalFilename: vi && vi.strings ? vi.strings.OriginalFilename || null : null, version: vi && vi.fixed ? vi.fixed.fileVersion : null,
    signed: !!pe.certificates, signer: pe.certificates ? pe.certificates.commonNames.filter((n) => !/\b(CA|Authority|PCA|Root|Time[- ]?Stamp|Timestamp|TSA)\b/i.test(n))[0] || null : null,
    pdb: (pe.debug.find((d) => d.codeView && d.codeView.pdb) || { codeView: {} }).codeView.pdb || null,
    importedDlls: pe.imports.length + pe.delayImports.length, importedApis: pe.imports.reduce((n, d) => n + d.entries.length, 0) + pe.delayImports.reduce((n, d) => n + d.entries.length, 0),
    exports: pe.exports ? pe.exports.functions.length : 0, resources: pe.resources ? pe.resources.count : 0,
    aslr: oh ? oh.dllCharacteristicsFlags.includes('DYNAMIC_BASE') : null, dep: oh ? oh.dllCharacteristicsFlags.includes('NX_COMPAT') : null,
    cfg: oh ? oh.dllCharacteristicsFlags.includes('GUARD_CF') : null, dotnet: !!pe.clr,
  };
}

export function guessCompiler(pe) {
  const names = new Set(pe.sections.map((s) => s.name));
  const dlls = new Set([...pe.imports, ...pe.delayImports].map((d) => (d.name || '').toLowerCase()));
  const rich = pe.rich && pe.rich.valid ? pe.rich : null;
  const pdb = (pe.debug.find((d) => d.codeView && d.codeView.pdb) || { codeView: {} }).codeView.pdb || '';
  if (pe.clr) return `.NET (${pe.clr.runtimeVersion || 'CLR ' + pe.clr.majorRuntimeVersion + '.' + pe.clr.minorRuntimeVersion})`;
  if (names.has('.symtab') || names.has('.gopclntab') || [...names].some((n) => n.startsWith('.go'))) return 'Go';
  if (names.has('.idata') && names.has('.bss') && names.has('.CRT') && [...dlls].some((d) => d.startsWith('msvcrt'))) return 'MinGW GCC';
  if ([...names].some((n) => /^\.(eh_fram|buildid)/.test(n)) || [...dlls].some((d) => /libgcc|libstdc\+\+|msys-|cygwin1/.test(d))) return 'GCC (MinGW/Cygwin/MSYS)';
  if (names.has('CODE') && names.has('DATA') && names.has('BSS') && (names.has('.idata') || names.has('.tls'))) return 'Delphi / Borland';
  if ([...dlls].some((d) => /^msvbvm60|^vb[56]?[a-z]*\.dll$/.test(d))) return 'Visual Basic 6';
  if (/\\rustc\\|\.cargo\\|\/rustc\/|\.rs$|\\registry\\src/.test(pdb) || (dlls.has('bcryptprimitives.dll') && dlls.has('api-ms-win-core-synch-l1-2-0.dll'))) return rich ? 'Rust (MSVC toolchain)' : 'Rust';
  if ([...dlls].some((d) => /^python\d+\.dll$/.test(d)) || names.has('.pyi') ) return 'PyInstaller / Python';
  if (names.has('.ndata')) return 'NSIS installer';
  if ([...names].some((n) => /^\.itext$/.test(n)) || (pe.resources && pe.resources.types.some((t) => t.typeName === 'RCDATA' && (t.children || []).some((c) => /^(DVCLAL|PACKAGEINFO|TFORM)/i.test(c.name || ''))))) return 'Delphi';
  if (names.has('.nv_fatb')) return 'CUDA';
  if (rich) {
    const link = rich.entries.find((e) => /Linker/.test(e.name || ''));
    const tc = link ? richToolchainLabel(link) : null;
    return `MSVC${tc ? ' (' + tc + ')' : ''}`;
  }
  if (pe.optionalHeader && pe.optionalHeader.majorLinkerVersion >= 6 && pe.optionalHeader.majorLinkerVersion <= 14 && [...dlls].some((d) => /^(msvcr|vcruntime|msvcp|api-ms-win-crt)/.test(d))) return 'MSVC';
  if ([...dlls].some((d) => /^qt\d|^qt5|^qt6/.test(d))) return 'Qt';
  if (pe.optionalHeader && pe.optionalHeader.majorLinkerVersion === 2 && pe.optionalHeader.minorLinkerVersion >= 20) return 'GCC (ld 2.x)';
  return null;
}
// Visual Studio generation for a Rich header entry. Two numbering schemes: linker-family tools
// (Linker, Implib, Export, Cvtres, Masm, AliasObj, Cvtomf) count 800=VS2005 ... 1400=VS2015+, while
// compiler-family tools (Utc, Phx, Cvtpgd) count 1400=VS2005 ... 1900=VS2015+. Inside the 2015+ bucket
// only the build number tells 2015/2017/2019/2022 apart.
export function richGeneration(entry) {
  const name = entry.name || '';
  const m = name.match(/^(Linker|Implib|Export|Cvtres|Masm|AliasObj|Cvtomf|Utc|Phx|Cvtpgd)(\d{3,4})/);
  if (!m) return entry.toolchain || null;
  const linkerFamily = !/^(Utc|Phx|Cvtpgd)$/.test(m[1]);
  const v = m[2];
  const byBuild = (b) => (b < 24000 ? 'VS 2015' : b < 25000 ? 'VS 2015 Update' : b < 27000 ? 'VS 2017' : b < 30000 ? 'VS 2019' : 'VS 2022');
  if (linkerFamily) {
    const gen = { '510': 'VS 5', '511': 'VS 5', '512': 'VS 5', '600': 'VS 6', '601': 'VS 6', '610': 'VS 6', '613': 'VS 6', '614': 'VS 6', '615': 'VS 6', '620': 'VS 6', '621': 'VS 6', '622': 'VS 6', '624': 'VS 6',
      '700': 'VS .NET 2002', '710': 'VS .NET 2003', '800': 'VS 2005', '900': 'VS 2008', '1000': 'VS 2010', '1010': 'VS 2010 SP1', '1100': 'VS 2012', '1200': 'VS 2013', '1210': 'VS 2013 Update' }[v];
    return gen || (v === '1400' ? byBuild(entry.build) : entry.toolchain || null);
  }
  const gen = { '11': 'VS 5', '12': 'VS 6', '13': 'VS .NET 2002', '1310': 'VS .NET 2003', '1400': 'VS 2005', '1500': 'VS 2008', '1600': 'VS 2010', '1610': 'VS 2010 SP1',
    '1700': 'VS 2012', '1800': 'VS 2013', '1810': 'VS 2013 Update' }[v];
  return gen || (v === '1900' ? byBuild(entry.build) : entry.toolchain || null);
}
function richToolchainLabel(entry) { return richGeneration(entry); }
