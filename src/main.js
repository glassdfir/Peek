// Peek UI. Pure DOM, no framework. The parser (pe.js) and triage (analyze.js)
// never touch the DOM, so they are shared with the tests and the CLI.
import { parsePE, toJSON, attachLookups, hex } from './pe.js';
import { analyze, richGeneration } from './analyze.js';
import ParseWorker from './worker.js?worker&inline';
import sampleUrl from '../test/corpus/t32.exe?url';
import { VERSION } from './version.js';
import { caseItems } from './suite.js';
import { buildArclight } from './arclight.js';
import { isZip, readZip, findPassword, checkPassword, classifyEntries, extractEntry, baseName, ZipError } from './zip.js';

const $ = (s, el = document) => el.querySelector(s);
const content = $('#content'), toc = $('#toc'), toast = $('#toast');
let current = null; // { name, size, pe, analysis }

// ---------- tiny DOM helper ----------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs && typeof attrs === 'object' && !(attrs instanceof Node) && !Array.isArray(attrs)) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true ? '' : v);
    }
  } else if (attrs !== undefined) children.unshift(attrs);
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const mono = (s) => h('code', { class: 'mono' }, s);
const chip = (text, cls = '') => h('span', { class: `chip ${cls}` }, text);
const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
const hx = (n, w = 8) => mono(hex(n, w));
const kv = (pairs) => h('dl', { class: 'kv' }, pairs.filter((p) => p && p[1] !== undefined && p[1] !== null && p[1] !== '').map(([k, v]) => [h('dt', k), h('dd', v)]));
const numOrHex = (n) => (typeof n === 'bigint' ? '0x' + n.toString(16) : typeof n === 'string' ? n : `${hex(n)} (${n})`);

function showToast(text) { toast.textContent = text; toast.classList.add('show'); clearTimeout(showToast.t); showToast.t = setTimeout(() => toast.classList.remove('show'), 1600); }
async function copyText(text, btn) {
  try { await navigator.clipboard.writeText(text); }
  catch (e) { const ta = h('textarea', { style: 'position:fixed;opacity:0' }, text); document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove(); }
  if (btn) { btn.classList.add('done'); btn.textContent = 'copied'; setTimeout(() => { btn.classList.remove('done'); btn.textContent = 'copy'; }, 1200); }
  else showToast('Copied');
}
const copyBtn = (text) => h('button', { type: 'button', class: 'copy', onclick: (e) => copyText(text, e.currentTarget) }, 'copy');

// ---------- loading ----------
async function loadFile(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  openBytes(file.name, bytes);
}
// Every way in (drop, Open file, ?src=, a hand-off) goes through here so a ZIP is unpacked first.
function openBytes(name, bytes) {
  if (isZip(bytes)) openZip(name, bytes);
  else load(name, bytes);
}
// Parsing runs in a Web Worker so hashing a large installer does not freeze the page.
// If the worker cannot start (some file:// setups, odd CSP), fall back to the main thread.
let worker = null, workerBroken = false;
function getWorker() {
  if (workerBroken) return null;
  if (!worker) { try { worker = new ParseWorker(); } catch (e) { workerBroken = true; console.warn('worker unavailable, parsing on the main thread', e); } }
  return worker;
}
function showCrash(name, error) {
  content.replaceChildren(h('div', { class: 'card' }, h('b', 'Parser crashed on ' + name + ': '), h('pre', { class: 'text' }, String(error)), h('p', 'That is a bug in Peek, not a verdict on the file. Please report it with the file hash; the JSON export is unavailable for this file.')));
  console.error(error);
}
function parseOnMainThread(name, bytes) {
  try {
    const pe = parsePE(bytes);
    return { ok: true, pe: toJSON(pe), analysis: analyze(pe, { fileName: name }) };
  } catch (e) { return { ok: false, error: e && e.stack || String(e) }; }
}
function load(name, bytes, origin = null) {
  const size = bytes.byteLength;
  const status = h('p', { class: 'status' }, `Parsing ${name} (${fmtSize(size)})…`);
  content.replaceChildren(status);
  toc.hidden = true;
  $('#exportBtn').disabled = true;
  const token = (load.token = {});
  const finish = (res) => {
    if (load.token !== token) return; // a newer file replaced this one
    if (!res.ok) { showCrash(name, res.error); return; }
    current = { name, size, pe: attachLookups(res.pe), analysis: res.analysis, bytes: bytes.byteLength ? bytes : null, origin };
    $('#exportBtn').disabled = false;
    $('#caseBtn').disabled = false;
    $('#hexesBtn').disabled = !current.bytes;
    render();
  };
  const w = getWorker();
  if (!w) { setTimeout(() => finish(parseOnMainThread(name, bytes)), 20); return; }
  const slow = setTimeout(() => { status.textContent = `Still hashing ${name} (${fmtSize(size)})… large files take a few seconds.`; }, 1500);
  w.onmessage = (e) => { clearTimeout(slow); finish(e.data); };
  w.onerror = (e) => {
    clearTimeout(slow);
    console.warn('worker failed, parsing on the main thread', e);
    workerBroken = true; worker = null;
    if (bytes.byteLength) setTimeout(() => finish(parseOnMainThread(name, bytes)), 20);
    else showCrash(name, 'The parsing worker failed and the file buffer was already handed to it. Reload the page and try again.');
  };
  // Small files are copied so the main-thread fallback still has them; big ones are transferred to avoid doubling memory.
  const transfer = size > 64 * 1024 * 1024;
  w.postMessage({ name, buffer: bytes.buffer }, transfer ? [bytes.buffer] : []);
}

// ---------- ZIP archives ----------
// Malware is shared as ZIPs locked with "infected". Peek opens them in the page (src/zip.js):
// try "infected", else ask; one executable opens straight away, several get a picker.
// The extracted bytes are only ever handed to the parser, exactly as if dropped directly.
const tick = () => new Promise((r) => setTimeout(r, 20));
const ZIP_TITLES = { 'not-zip': 'Not a ZIP archive', truncated: 'The ZIP is truncated', corrupt: 'The ZIP is damaged', 'too-big': 'Too large to extract', crc: 'Integrity check failed', unsupported: 'Cannot open this ZIP', 'bad-password': 'Wrong password', 'need-password': 'Password needed' };
function busy(text) {
  content.replaceChildren(h('p', { class: 'status' }, text));
  toc.hidden = true;
  $('#exportBtn').disabled = true; $('#caseBtn').disabled = true; $('#hexesBtn').disabled = true;
}
function zipProblem(zipName, err, actions = []) {
  if (!(err instanceof ZipError)) { showCrash(zipName, err && err.stack || err); return; }
  content.replaceChildren(h('section', { class: 'block' }, h('h2', zipName, h('span', { class: 'sub' }, 'ZIP archive')),
    h('div', { class: 'card zip-problem' }, h('h3', ZIP_TITLES[err.code] || 'Cannot open this ZIP'), h('p', err.message),
      h('p', { class: 'muted' }, 'Nothing was extracted or run.'), actions.length ? h('p', actions) : null)));
}
function askPassword(zipName, message) {
  const dlg = $('#zipPw'), input = $('#zipPwInput');
  $('#zipPwName').textContent = zipName;
  $('#zipPwMsg').textContent = message;
  input.value = '';
  dlg.returnValue = '';
  dlg.showModal();
  input.focus();
  return new Promise((resolve) => dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok' ? input.value : null), { once: true }));
}
async function openZip(zipName, bytes) {
  load.token = {}; // a parse still running for an earlier file must not replace this view
  busy(`Opening ${zipName} (${fmtSize(bytes.length)})…`);
  await tick();
  let files, password;
  try {
    files = readZip(bytes).entries.filter((e) => !e.dir);
    if (!files.length) throw new ZipError('corrupt', 'The archive contains no files.');
    password = findPassword(bytes, files);
  } catch (e) { return zipProblem(zipName, e); }
  const locked = files.find((e) => e.encrypted);
  let prompt = `Not "infected". Enter the password for this archive (${locked && locked.encryption}).`;
  while (password === null) {
    const pw = await askPassword(zipName, prompt);
    if (pw === null) return zipProblem(zipName, new ZipError('need-password', 'The archive is encrypted and its password is not "infected".'), [h('button', { type: 'button', class: 'copy', onclick: () => openZip(zipName, bytes) }, 'Enter password…')]);
    try { if (checkPassword(bytes, locked, pw)) password = pw; else prompt = 'That password did not work. Try again.'; }
    catch (e) { return zipProblem(zipName, e); }
  }
  busy(`Looking inside ${zipName}…`);
  await tick();
  let items;
  try { items = classifyEntries(bytes, files, password); } catch (e) { return zipProblem(zipName, e); }
  const zip = { name: zipName, bytes, items, password };
  const exes = items.filter((i) => i.kind === 'pe' || i.kind === 'mz');
  if (exes.length === 1) return openEntry(zip, exes[0].entry);
  if (items.every((i) => i.kind === 'error')) return zipProblem(zipName, items[0].error); // nothing usable: say why plainly
  showZipPicker(zip);
}
function showZipPicker(zip) {
  load.token = {};
  const exes = zip.items.filter((i) => i.kind === 'pe' || i.kind === 'mz');
  const kindChip = (i) => i.kind === 'pe' ? chip('PE', 'info') : i.kind === 'mz' ? chip('MZ header', 'info') : i.kind === 'error' ? chip(i.error.message, 'medium') : chip('not an executable');
  const rows = [...exes, ...zip.items.filter((i) => !exes.includes(i))].map((i) => h('tr', { class: i.kind === 'error' ? 'muted' : '' },
    h('td', { class: 'mono wrap' }, i.entry.displayName), h('td', { class: 'num' }, fmtSize(i.entry.size)), h('td', i.entry.encryption === 'none' ? '—' : i.entry.encryption), h('td', kindChip(i)),
    h('td', h('button', { type: 'button', class: 'copy', disabled: i.kind === 'error', onclick: () => openEntry(zip, i.entry) }, exes.includes(i) ? 'Open' : 'Open anyway'))));
  const lead = exes.length > 1 ? `${exes.length} Windows executables in this archive. Pick one to analyze.`
    : 'No Windows executable (MZ header) in this archive. You can still open a file; Peek will report what it finds.';
  content.replaceChildren(h('section', { class: 'block', id: 'zip' }, h('h2', zip.name, h('span', { class: 'sub' }, `ZIP archive · ${zip.items.length} file${zip.items.length === 1 ? '' : 's'}${zip.password ? ` · password "${zip.password}"` : ''}`)),
    h('p', lead),
    h('div', { class: 'table-wrap' }, h('table', h('thead', h('tr', h('th', 'Name'), h('th', 'Size'), h('th', 'Encryption'), h('th', 'Looks like'), h('th', ''))), h('tbody', rows)))));
  toc.hidden = true;
  $('#exportBtn').disabled = true; $('#caseBtn').disabled = true; $('#hexesBtn').disabled = true;
}
async function openEntry(zip, entry) {
  busy(`Extracting ${entry.displayName} from ${zip.name} (${fmtSize(entry.size)})…`);
  await tick();
  const back = zip.items.length > 1 ? [h('button', { type: 'button', class: 'copy', onclick: () => showZipPicker(zip) }, 'Back to the file list')] : [];
  let data;
  for (;;) {
    try { data = extractEntry(zip.bytes, entry, { password: zip.password }); break; }
    catch (e) {
      if (!(e instanceof ZipError) || (e.code !== 'bad-password' && e.code !== 'need-password')) return zipProblem(zip.name, e, back);
      // This entry has a different password from the one that opened the archive.
      const pw = await askPassword(zip.name, `${entry.displayName} needs a different password.`);
      if (pw === null) return zipProblem(zip.name, e, back);
      zip.password = pw;
    }
  }
  load(baseName(entry.name), data, { archive: zip.name, path: entry.displayName, encryption: entry.encryption, password: entry.encrypted ? zip.password : null, zip: zip.items.length > 1 ? zip : null });
}

// ---------- rendering ----------
function render() {
  const { name, size, pe, analysis: a } = current;
  const blocks = [];
  const sec = (id, title, sub, ...body) => { const s = h('section', { class: 'block', id }, h('h2', title, sub ? h('span', { class: 'sub' }, sub) : null), ...body); blocks.push({ id, title, el: s }); return s; };

  // Summary
  const s = a.summary;
  const summary = sec('summary', name, `${fmtSize(size)} · ${size} bytes`);
  const o = current.origin;
  if (o) summary.append(h('div', { class: 'card origin' }, chip('from ZIP', 'info'), ' Extracted in the browser from ', mono(o.archive), ', entry ', mono(o.path),
    o.encryption !== 'none' ? ` (${o.encryption}${o.password ? `, password "${o.password}"` : ''})` : ' (not encrypted)', '. Hashes, findings and hand-offs are for the extracted file.',
    o.zip ? [' ', h('button', { type: 'button', class: 'copy', onclick: () => showZipPicker(o.zip) }, 'Other files in this ZIP')] : null));
  if (pe.errors.length) summary.append(h('div', { class: 'card' }, pe.errors.map((e) => h('p', chip('error', 'high'), ' ', e))));
  if (s) {
    const posture = [
      chip(s.kind, 'info'), chip(s.machine, 'info'), chip(s.format, 'info'), chip(s.subsystem, 'info'),
      s.signed ? chip(`signed${s.signer ? ': ' + s.signer : ''}`, 'ok') : chip('unsigned'),
      chip(`ASLR ${s.aslr ? 'on' : 'off'}`, s.aslr ? 'ok' : ''), chip(`DEP ${s.dep ? 'on' : 'off'}`, s.dep ? 'ok' : ''), chip(`CFG ${s.cfg ? 'on' : 'off'}`, s.cfg ? 'ok' : ''),
      s.dotnet ? chip('.NET', 'info') : null, s.packer ? chip(`packer: ${s.packer}`, 'high') : null,
      a.counts.high ? chip(`${a.counts.high} high`, 'high') : null, a.counts.medium ? chip(`${a.counts.medium} medium`, 'medium') : null,
      a.counts.low ? chip(`${a.counts.low} low`, 'low') : null, a.counts.info ? chip(`${a.counts.info} info`, 'info') : null,
    ];
    const hashes = h('div', { class: 'card hashes' }, h('h3', 'Hashes'),
      [['sha256', pe.hashes.sha256], ['sha1', pe.hashes.sha1], ['md5', pe.hashes.md5], ['imphash', pe.hashes.imphash], ['rich', pe.hashes.richHash]]
        .map(([k, v]) => h('div', { class: 'row' }, h('b', k), v ? [mono(v), copyBtn(v)] : h('span', { class: 'empty' }, k === 'imphash' ? 'no imports' : 'no Rich header'))),
      h('div', { class: 'row', style: 'margin-top:6px' }, h('button', { type: 'button', class: 'copy', onclick: () => copyText(`${name}\nsha256 ${pe.hashes.sha256}\nsha1   ${pe.hashes.sha1}\nmd5    ${pe.hashes.md5}\nimphash ${pe.hashes.imphash || '-'}\nrich   ${pe.hashes.richHash || '-'}`) }, 'copy all')));
    const identity = h('div', { class: 'card' }, h('h3', 'Identity'), kv([
      ['Description', s.description], ['Company', s.company], ['Version', s.version], ['Original name', s.originalFilename],
      ['Compiled', s.compiled || h('span', { class: 'empty' }, 'timestamp is zero')], ['Toolchain', [s.compiler, s.linker ? ` (linker ${s.linker})` : ''].join('') || h('span', { class: 'empty' }, 'unknown')],
      ['PDB', s.pdb ? mono(s.pdb) : null], ['Signer', s.signer],
      ['Imports', `${s.importedApis} functions from ${s.importedDlls} DLLs`], ['Exports', s.exports || null], ['Resources', s.resources || null],
    ]));
    const ep = pe.entryPoint;
    const epCard = ep ? h('div', { class: 'card' }, h('h3', 'Entry point'), kv([
      ['RVA', hx(ep.rva)], ['Section', ep.section || h('span', { class: 'chip high' }, 'none')], ['File offset', ep.offset !== null ? hx(ep.offset) : h('span', { class: 'chip high' }, 'no file data')],
      ['Bytes', ep.bytes.length ? h('pre', { class: 'hex' }, ep.bytes.map((b) => b.toString(16).padStart(2, '0')).join(' ')) : null],
    ])) : null;
    summary.append(h('div', { style: 'margin-bottom:12px' }, posture), h('div', { class: 'cards' }, identity, hashes, epCard));
  }

  // Findings
  const findings = sec('findings', 'Findings', `${a.findings.length} observation${a.findings.length === 1 ? '' : 's'}; context, not a verdict`);
  if (!a.findings.length) findings.append(h('p', { class: 'empty' }, 'Nothing unusual.'));
  else {
    const list = h('div', { class: 'card' });
    const state = { high: true, medium: true, low: true, info: true };
    const draw = () => list.replaceChildren(...a.findings.filter((f) => state[f.severity]).map((f) => h('div', { class: 'finding' }, chip(f.severity, f.severity), h('div', h('div', { class: 'title' }, f.title), f.detail ? h('div', { class: 'detail' }, f.detail) : null))));
    const bar = h('div', { class: 'sevbar' }, ['high', 'medium', 'low', 'info'].map((sv) => h('label', h('input', { type: 'checkbox', checked: true, onchange: (e) => { state[sv] = e.target.checked; draw(); } }), chip(`${sv} ${a.counts[sv]}`, sv))));
    draw();
    findings.append(bar, list);
  }
  if (a.notableImports.length) findings.append(h('div', { class: 'card', style: 'margin-top:12px' }, h('h3', 'Notable imports'), h('div', { class: 'notable' }, a.notableImports.map((g) => [h('b', g.group), h('span', g.apis.join(', '))]))));

  // Headers
  if (pe.fileHeader) {
    const fh = pe.fileHeader, oh = pe.optionalHeader;
    const headers = sec('headers', 'Headers');
    const cards = [];
    cards.push(h('div', { class: 'card' }, h('h3', 'DOS header'), kv([['e_magic', mono('MZ')], ['e_lfanew', hx(pe.dos.e_lfanew)], ['Rich header', pe.rich ? (pe.rich.valid ? chip('present, checksum valid', 'ok') : chip('present, checksum INVALID', 'medium')) : 'none']])));
    cards.push(h('div', { class: 'card' }, h('h3', 'File header'), kv([
      ['Machine', [hx(fh.machine, 4), ' ', fh.machineName]], ['Sections', fh.numberOfSections], ['Timestamp', [hx(fh.timeDateStamp), ' ', fh.timestamp || h('span', { class: 'empty' }, 'zero')]],
      ['Symbol table', fh.pointerToSymbolTable ? `${hex(fh.pointerToSymbolTable)} (${fh.numberOfSymbols} symbols)` : null], ['Optional hdr size', hx(fh.sizeOfOptionalHeader, 2)],
      ['Characteristics', [hx(fh.characteristics, 4), h('div', fh.characteristicsFlags.map((f) => chip(f, 'flag')))]],
    ])));
    if (oh) cards.push(h('div', { class: 'card' }, h('h3', `Optional header (${oh.format})`), kv([
      ['Magic', hx(oh.magic, 3)], ['Linker', oh.linkerVersion], ['Entry point', hx(oh.addressOfEntryPoint)], ['Image base', mono(typeof oh.imageBase === 'bigint' ? '0x' + oh.imageBase.toString(16) : hex(oh.imageBase, oh.is64 ? 16 : 8))],
      ['Base of code', hx(oh.baseOfCode)], ['Base of data', oh.baseOfData !== undefined ? hx(oh.baseOfData) : null],
      ['Size of code / init / uninit', `${hex(oh.sizeOfCode)} / ${hex(oh.sizeOfInitializedData)} / ${hex(oh.sizeOfUninitializedData)}`],
      ['Section / file align', `${hex(oh.sectionAlignment)} / ${hex(oh.fileAlignment)}`], ['Size of image / headers', `${hex(oh.sizeOfImage)} / ${hex(oh.sizeOfHeaders)}`],
      ['OS / image / subsystem ver', `${oh.osVersion} / ${oh.imageVersion} / ${oh.subsystemVersion}`], ['Subsystem', `${oh.subsystem} ${oh.subsystemName}`],
      ['Checksum', pe.checksum ? [hx(pe.checksum.stored), ' ', pe.checksum.stored === 0 ? chip('not set') : pe.checksum.matches ? chip('valid', 'ok') : chip(`mismatch, computed ${hex(pe.checksum.computed)}`, 'medium')] : null],
      ['DLL characteristics', [hx(oh.dllCharacteristics, 4), h('div', oh.dllCharacteristicsFlags.map((f) => chip(f, 'flag')))]],
      ['Stack reserve / commit', `${numOrHex(oh.sizeOfStackReserve)} / ${numOrHex(oh.sizeOfStackCommit)}`], ['Heap reserve / commit', `${numOrHex(oh.sizeOfHeapReserve)} / ${numOrHex(oh.sizeOfHeapCommit)}`],
      ['Loader flags', oh.loaderFlags ? hx(oh.loaderFlags) : null], ['RVA & sizes', oh.numberOfRvaAndSizes],
    ])));
    headers.append(h('div', { class: 'cards' }, cards));
    if (pe.dataDirectories) {
      headers.append(h('h3', { style: 'margin:16px 0 6px;font-size:13px' }, 'Data directories'), h('div', { class: 'table-wrap' }, h('table',
        h('thead', h('tr', h('th', '#'), h('th', 'Directory'), h('th', 'RVA'), h('th', 'Size'), h('th', 'Section'))),
        h('tbody', pe.dataDirectories.map((d) => {
          const secn = d.rva ? (d.index === 4 ? '(file offset)' : (pe.sectionFor(d.rva) || {}).displayName || (d.rva < (oh ? oh.sizeOfHeaders : 0) ? 'headers' : h('span', { class: 'chip medium' }, 'unmapped'))) : '';
          return h('tr', { class: d.rva ? '' : 'muted' }, h('td', d.index), h('td', d.name), h('td', { class: 'mono' }, d.rva ? hex(d.rva, 8) : '—'), h('td', { class: 'mono' }, d.size ? hex(d.size) : '—'), h('td', secn));
        })))));
    }
  }

  // Sections
  const sections = sec('sections', 'Sections', `${pe.sections.length}`);
  if (!pe.sections.length) sections.append(h('p', { class: 'empty' }, 'No section table.'));
  else sections.append(h('div', { class: 'table-wrap' }, h('table',
    h('thead', h('tr', h('th', 'Name'), h('th', 'Virtual addr'), h('th', 'Virtual size'), h('th', 'Raw offset'), h('th', 'Raw size'), h('th', 'Perm'), h('th', 'Entropy'), h('th', 'MD5'), h('th', 'Flags'))),
    h('tbody', pe.sections.map((x) => {
      const isEp = pe.entryPoint && pe.entryPoint.sectionIndex === x.index;
      const cls = [isEp ? 'ep' : '', (x.executable && x.writable) || x.truncated || (x.entropy > 7.2 && x.executable) ? 'bad' : x.entropy > 7.2 || (x.sizeOfRawData === 0 && x.virtualSize && x.executable) ? 'warn' : ''].join(' ');
      const hot = x.entropy > 7.2;
      return h('tr', { class: cls }, h('td', { class: 'mono' }, x.displayName), h('td', { class: 'mono' }, hex(x.virtualAddress, 8)), h('td', { class: 'mono' }, hex(x.virtualSize, 8)),
        h('td', { class: 'mono' }, hex(x.pointerToRawData, 8)), h('td', { class: 'mono' }, [hex(x.sizeOfRawData, 8), x.truncated ? [' ', chip('truncated', 'high')] : null]),
        h('td', { class: 'mono' }, `${x.readable ? 'R' : '-'}${x.writable ? 'W' : '-'}${x.executable ? 'X' : '-'}`),
        h('td', h('span', { class: `bar ${hot ? 'hot' : ''}`, title: 'Shannon entropy 0–8' }, h('i', { style: `width:${(x.entropy / 8) * 100}%` })), x.entropy.toFixed(2)),
        h('td', { class: 'mono' }, x.md5 || '—'), h('td', x.flags.filter((f) => !/^MEM_(READ|WRITE|EXECUTE)$/.test(f)).map((f) => chip(f, 'flag'))));
    })))));

  // Imports
  const allImports = [...pe.imports, ...pe.delayImports];
  const nApis = allImports.reduce((n, d) => n + d.entries.length, 0);
  const imports = sec('imports', 'Imports', `${nApis} functions from ${allImports.length} modules${pe.delayImports.length ? ` (${pe.delayImports.length} delay-loaded)` : ''}`);
  if (!allImports.length) imports.append(h('p', { class: 'empty' }, pe.clr ? 'No native import table (managed code imports via metadata).' : 'No import table.'));
  else {
    const list = h('div');
    const filter = h('input', { type: 'search', placeholder: 'Filter functions or DLLs…', oninput: () => drawImports(list, allImports, filter.value) });
    imports.append(h('div', { class: 'toolbar' }, filter, h('button', { type: 'button', class: 'copy', onclick: () => list.querySelectorAll('details').forEach((d) => (d.open = true)) }, 'expand all'),
      h('button', { type: 'button', class: 'copy', onclick: () => list.querySelectorAll('details').forEach((d) => (d.open = false)) }, 'collapse all'),
      h('button', { type: 'button', class: 'copy', onclick: () => copyText(allImports.map((d) => `${d.name}${d.delay ? ' (delay)' : ''}\n` + d.entries.map((e) => '  ' + e.display).join('\n')).join('\n')) }, 'copy list')), list);
    drawImports(list, allImports, '');
  }
  if (pe.boundImports && pe.boundImports.length) imports.append(h('p', { class: 'muted' }, 'Bound imports: ', pe.boundImports.map((b) => `${b.name} (${b.timestamp || hex(b.timeDateStamp)})`).join(', ')));

  // Exports
  const ex = pe.exports;
  const exportsSec = sec('exports', 'Exports', ex ? `${ex.functions.length} from ${ex.name || '(unnamed)'}` : '');
  if (!ex) exportsSec.append(h('p', { class: 'empty' }, 'No export table.'));
  else {
    const tbody = h('tbody');
    const draw = (q) => tbody.replaceChildren(...ex.functions.filter((f) => !q || (f.name || '').toLowerCase().includes(q) || (f.forwarder || '').toLowerCase().includes(q) || String(f.ordinal) === q).slice(0, 5000)
      .map((f) => h('tr', h('td', { class: 'num' }, f.ordinal), h('td', { class: 'mono' }, f.forwarder ? '→ ' + f.forwarder : hex(f.rva, 8)), h('td', { class: 'mono' }, f.names.length ? f.names.join(', ') : h('span', { class: 'muted' }, '(by ordinal only)')), h('td', f.section || (f.forwarder ? 'forwarder' : h('span', { class: 'chip medium' }, 'unmapped'))))));
    const filter = h('input', { type: 'search', placeholder: 'Filter exports…', oninput: () => draw(filter.value.toLowerCase()) });
    exportsSec.append(h('div', { class: 'toolbar' }, filter, h('span', { class: 'muted' }, `ordinal base ${ex.ordinalBase} · ${ex.numberOfNames} named · export timestamp ${ex.timestamp || hex(ex.timeDateStamp)}${ex.note ? ' · ' + ex.note : ''}`)),
      h('div', { class: 'table-wrap' }, h('table', h('thead', h('tr', h('th', 'Ordinal'), h('th', 'RVA / forwarder'), h('th', 'Name'), h('th', 'Section'))), tbody)));
    draw('');
  }

  // Resources
  const rs = pe.resources;
  const resSec = sec('resources', 'Resources', rs ? `${rs.count} entries, ${fmtSize(rs.totalSize)}` : '');
  if (!rs) resSec.append(h('p', { class: 'empty' }, 'No resource directory.'));
  else {
    const vi = rs.versionInfo;
    const cards = [];
    if (vi) cards.push(h('div', { class: 'card' }, h('h3', 'Version info'), kv([
      ...Object.entries(vi.strings || {}).map(([k, v]) => [k, v]),
      ['File version (fixed)', vi.fixed ? vi.fixed.fileVersion : null], ['Product version (fixed)', vi.fixed ? vi.fixed.productVersion : null], ['File type', vi.fixed ? vi.fixed.fileTypeName : null],
      ['Translations', vi.translations.length ? vi.translations.map((t) => `lang ${hex(t.lang, 4)} cp ${t.codePage}`).join(', ') : null],
    ])));
    if (rs.manifest) cards.push(h('div', { class: 'card wide' }, h('h3', 'Manifest'), h('pre', { class: 'text' }, rs.manifest.trim())));
    if (cards.length) resSec.append(h('div', { class: 'cards', style: 'margin-bottom:12px' }, cards));
    resSec.append(h('div', { class: 'table-wrap' }, h('table', h('thead', h('tr', h('th', 'Type'), h('th', 'Name / ID'), h('th', 'Lang'), h('th', 'RVA'), h('th', 'Size'), h('th', 'Entropy'), h('th', 'Looks like'))),
      h('tbody', rs.items.slice(0, 2000).map((it) => h('tr', { class: it.magic === 'PE/DOS executable' ? 'bad' : it.entropy > 7.5 && it.size > 8192 && !/ICON|PNG|BITMAP/.test(it.type) ? 'warn' : '' },
        h('td', it.type), h('td', { class: 'mono' }, it.name), h('td', { class: 'mono' }, it.lang !== null ? hex(it.lang, 4) : ''), h('td', { class: 'mono' }, hex(it.rva, 8)), h('td', { class: 'num' }, fmtSize(it.size)),
        h('td', it.entropy.toFixed(2)), h('td', it.magic || '', it.bad ? [' ', chip('unmapped', 'medium')] : null)))))));
  }

  // Debug & toolchain
  const dbg = sec('debug', 'Debug & toolchain');
  const dcards = [];
  if (pe.debug.length) dcards.push(h('div', { class: 'card wide' }, h('h3', 'Debug directory'), h('div', { class: 'scroll' }, h('table', h('thead', h('tr', h('th', 'Type'), h('th', 'Timestamp'), h('th', 'Details'))),
    h('tbody', pe.debug.map((d) => h('tr', h('td', d.typeName), h('td', { class: 'mono' }, d.timestamp || hex(d.timeDateStamp)),
      h('td', { class: 'wrap' }, d.codeView ? [d.codeView.pdb ? mono(d.codeView.pdb) : null, d.codeView.guid ? h('div', { class: 'muted mono' }, `${d.codeView.guid} age ${d.codeView.age}`) : null] : d.repro ? mono(d.repro.hash) : d.pogo ? d.pogo.signature : d.cetCompat !== undefined ? (d.cetCompat ? 'CET compatible' : 'CET not set') : d.error ? h('span', { class: 'chip medium' }, d.error) : h('span', { class: 'muted' }, `${d.sizeOfData} bytes at ${hex(d.pointerToRawData)}`)))))))));
  else dcards.push(h('div', { class: 'card' }, h('h3', 'Debug directory'), h('p', { class: 'empty' }, 'None.')));
  if (pe.rich) dcards.push(h('div', { class: 'card wide' }, h('h3', 'Rich header'), h('p', { style: 'margin:0 0 6px' }, pe.rich.valid ? chip('checksum valid', 'ok') : chip('checksum invalid: edited or forged', 'medium'), ' ', mono(`key ${hex(pe.rich.key, 8)}`), ' ', pe.rich.hash ? [mono(`hash ${pe.rich.hash}`)] : null),
    h('div', { class: 'scroll' }, h('table', h('thead', h('tr', h('th', 'Tool'), h('th', 'Product id'), h('th', { class: 'num' }, 'Build'), h('th', { class: 'num' }, 'Count'), h('th', 'Generation'))),
      h('tbody', pe.rich.entries.map((e) => h('tr', h('td', { class: 'mono' }, e.name || h('span', { class: 'muted' }, 'unknown')), h('td', { class: 'mono' }, hex(e.productId, 4)), h('td', { class: 'num' }, e.build), h('td', { class: 'num' }, e.count), h('td', richGeneration(e) || ''))))))));
  else dcards.push(h('div', { class: 'card' }, h('h3', 'Rich header'), h('p', { class: 'empty' }, 'None (not linked with Microsoft link.exe, or stripped).')));
  if (pe.tls) dcards.push(h('div', { class: 'card' }, h('h3', 'TLS'), kv([['Raw data', `${numOrHex(pe.tls.startAddressOfRawData)} – ${numOrHex(pe.tls.endAddressOfRawData)}`], ['Index', numOrHex(pe.tls.addressOfIndex)], ['Callbacks', pe.tls.callbacks.length ? h('div', pe.tls.callbacks.map((c) => h('div', mono(`${hex(c.rva, 8)}`), ' in ', c.section || h('span', { class: 'chip medium' }, 'no section')))) : pe.tls.callbacksNote || 'none'], ['Zero fill', hx(pe.tls.sizeOfZeroFill)]])));
  if (pe.clr) dcards.push(h('div', { class: 'card' }, h('h3', '.NET (CLR) header'), kv([['Runtime', pe.clr.runtimeVersion || `${pe.clr.majorRuntimeVersion}.${pe.clr.minorRuntimeVersion}`], ['Flags', h('div', pe.clr.flagNames.map((f) => chip(f, 'flag')))], ['Entry token', hx(pe.clr.entryPointToken)], ['Metadata', `${hex(pe.clr.metaDataRva)} (${fmtSize(pe.clr.metaDataSize)}${pe.clr.streams ? `, ${pe.clr.streams} streams` : ''})`], ['Strong name', pe.clr.strongNameSize ? `${pe.clr.strongNameSize} bytes` : 'none']])));
  if (pe.loadConfig) dcards.push(h('div', { class: 'card' }, h('h3', 'Load config'), kv([['Size', hx(pe.loadConfig.size)], ['Security cookie', pe.loadConfig.securityCookie !== undefined ? mono(numOrHex(pe.loadConfig.securityCookie)) : null], ['SEH handlers', pe.loadConfig.sehHandlerCount], ['Guard flags', pe.loadConfig.guardFlagNames ? h('div', pe.loadConfig.guardFlagNames.length ? pe.loadConfig.guardFlagNames.map((f) => chip(f, 'flag')) : 'none') : null]])));
  dcards.push(h('div', { class: 'card' }, h('h3', 'Other'), kv([['Relocations', pe.relocations ? `${pe.relocations.blocks} blocks, ${pe.relocations.entries} entries` : 'none'], ['Exception table', pe.exceptions ? `${pe.exceptions.count} functions` : 'none'], ['Delay imports', pe.delayImports.length || null]])));
  dbg.append(h('div', { class: 'cards' }, dcards));

  // Signature & overlay
  const sig = sec('signature', 'Signature & overlay');
  const scards = [];
  if (pe.certificates) {
    const c = pe.certificates;
    scards.push(h('div', { class: 'card' }, h('h3', 'Authenticode'), c.error ? h('p', chip(c.error, 'medium')) : [
      kv([['Location', `file offset ${hex(c.offset)}, ${fmtSize(c.size)}`], ['Blobs', c.entries.map((e) => `${e.typeName} rev ${hex(e.revision)} ${fmtSize(e.length)}${e.truncated ? ' (truncated)' : ''}`).join('; ')],
        ['Digest', c.entries[0] && c.entries[0].digestAlgorithm], ['Signing time', c.entries[0] && c.entries[0].signingTime], ['Names in blob', c.commonNames.length ? h('div', c.commonNames.map((n) => chip(n, 'flag'))) : null]]),
      h('p', { class: 'muted', style: 'margin:8px 0 0' }, 'Presence and names only. The chain and the file hash are not verified here.')]));
  } else scards.push(h('div', { class: 'card' }, h('h3', 'Authenticode'), h('p', { class: 'empty' }, 'Not signed (no security directory).')));
  if (pe.overlay) {
    const o = pe.overlay;
    scards.push(h('div', { class: 'card' }, h('h3', 'Overlay'), kv([['Offset', hx(o.offset)], ['Total', fmtSize(o.size)], ['Certificate bytes', o.certificateBytes ? fmtSize(o.certificateBytes) : null], ['Other data', o.dataSize ? `${fmtSize(o.dataSize)} (entropy ${o.entropy.toFixed(2)})` : 'none'], ['Looks like', o.magic], ['First bytes', o.head.length ? h('pre', { class: 'hex' }, o.head.map((b) => b.toString(16).padStart(2, '0')).join(' ')) : null]])));
  } else scards.push(h('div', { class: 'card' }, h('h3', 'Overlay'), h('p', { class: 'empty' }, 'None; the file ends with the last section.')));
  sig.append(h('div', { class: 'cards' }, scards));

  // Parser warnings
  if (pe.warnings.length) sec('warnings', 'Parser notes', `${pe.warnings.length}`).append(h('div', { class: 'card' }, pe.warnings.map((w) => h('div', { class: 'finding' }, chip(w.level, w.level === 'error' ? 'medium' : 'low'), h('div', w.text)))));

  // Raw JSON
  const raw = sec('json', 'JSON');
  const pre = h('pre', { class: 'text', style: 'max-height:480px' });
  raw.append(h('div', { class: 'toolbar' }, h('button', { type: 'button', class: 'copy', onclick: () => { pre.textContent = exportJson(); } }, 'show'), h('button', { type: 'button', class: 'copy', onclick: () => copyText(exportJson()) }, 'copy'), h('button', { type: 'button', class: 'copy', onclick: downloadJson }, 'download')), pre);

  content.replaceChildren(...blocks.map((b) => b.el));
  toc.hidden = false;
  toc.replaceChildren(...blocks.map((b) => {
    let count = null;
    if (b.id === 'findings') count = h('span', { class: `count ${a.counts.high ? 'hot' : ''}` }, a.findings.length);
    if (b.id === 'sections') count = h('span', { class: 'count' }, pe.sections.length);
    if (b.id === 'imports') count = h('span', { class: 'count' }, nApis);
    if (b.id === 'exports' && ex) count = h('span', { class: 'count' }, ex.functions.length);
    if (b.id === 'resources' && rs) count = h('span', { class: 'count' }, rs.count);
    return h('a', { href: '#' + b.id, onclick: (e) => { e.preventDefault(); b.el.scrollIntoView({ behavior: 'smooth', block: 'start' }); } }, b.title, count);
  }));
  content.scrollTop = 0;
  watchToc(blocks);
  // #imports, #findings, ... in the URL jumps to that section once the report exists
  const target = location.hash.length > 1 && document.getElementById(decodeURIComponent(location.hash.slice(1)));
  if (target && content.contains(target)) target.scrollIntoView({ block: 'start' });
}

function drawImports(list, dlls, q) {
  q = q.trim().toLowerCase();
  list.replaceChildren(...dlls.map((d) => {
    const fns = q ? d.entries.filter((e) => e.display.toLowerCase().includes(q)) : d.entries;
    const dllHit = q && (d.name || '').toLowerCase().includes(q);
    if (q && !fns.length && !dllHit) return null;
    const shown = dllHit && !fns.length ? d.entries : fns;
    return h('details', { class: 'dll', open: !!q || dlls.length <= 3 },
      h('summary', h('b', d.name), h('span', { class: 'n' }, `${d.entries.length} function${d.entries.length === 1 ? '' : 's'}`), d.delay ? chip('delay-load', 'info') : null, d.bound ? chip('bound', 'flag') : null, d.error ? chip('damaged', 'medium') : null, d.bad ? chip('bad name', 'medium') : null),
      h('div', { class: 'fns' }, shown.map((e) => h('span', { class: e.bad ? 'hl' : '' }, e.byOrdinal ? [h('span', { class: 'ord' }, `#${e.ordinal} `), e.display !== `ord${e.ordinal}` ? e.display : ''] : e.display))));
  }).filter(Boolean));
  if (!list.children.length) list.append(h('p', { class: 'empty' }, 'No matches.'));
}

function exportJson() {
  const { name, pe, analysis, origin } = current;
  const { findings, notableImports, counts, summary, packerHint } = analysis;
  return JSON.stringify({ file: name, ...(origin ? { extractedFrom: { archive: origin.archive, entry: origin.path, encryption: origin.encryption } } : {}), generator: `peek ${VERSION}`, note: 'Findings are observations, not verdicts. Signature data is presence and names only; the certificate chain and file hash were not verified.', ...toJSON(pe), analysis: { counts, packerHint, summary, findings, notableImports } }, null, 2);
}
function downloadJson() {
  const blob = new Blob([exportJson()], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: current.name.replace(/\.[^.]+$/, '') + '.peek.json' });
  document.body.append(a); a.click(); a.remove();
}

function watchToc(blocks) {
  if (watchToc.obs) watchToc.obs.disconnect();
  const links = [...toc.querySelectorAll('a')];
  const visible = new Set();
  watchToc.obs = new IntersectionObserver((entries) => {
    for (const e of entries) e.isIntersecting ? visible.add(e.target.id) : visible.delete(e.target.id);
    const first = blocks.find((b) => visible.has(b.id));
    links.forEach((l) => l.classList.toggle('active', !!first && l.getAttribute('href') === '#' + first.id));
  }, { root: content, rootMargin: '0px 0px -70% 0px' });
  blocks.forEach((b) => watchToc.obs.observe(b.el));
}

// ---------- suite hand-offs ----------
// On jon.glass the tools pass data to each other through /assets/suite/handoff.js (same-origin
// localStorage, nothing leaves the browser). The script is loaded only over http(s), so the
// single-file copy opened from disk never tries to fetch it; the buttons stay hidden there.
const suite = () => (window.Suite && window.Suite.available() ? window.Suite : null);
function openVia(promise) {
  // Open the tab first so popup blockers allow it, then point it at the hand-off URL.
  const w = window.open('', '_blank');
  promise.then((url) => { if (w) { w.opener = null; w.location.href = url; } else location.href = url; },
    (e) => { if (w) w.close(); showToast(e.message); });
}
function sendToTessera() {
  const S = suite();
  if (!S || !current) return;
  const { name, size, pe, analysis, origin } = current;
  openVia(S.send('peek', 'tessera', { kind: 'case', name: name.replace(/\.[^.]*$/, ''), data: JSON.stringify(caseItems({ name, size, pe, analysis, origin })) }));
}
function sendToHexes() {
  const S = suite();
  if (!S || !current) return;
  if (!current.bytes) return showToast('This file was too large to keep in memory for a hand-off. Open it in Hexes from disk.');
  const ep = current.pe.entryPoint;
  openVia(S.send('peek', 'hexes', { kind: 'bytes', name: current.name, data: current.bytes, meta: ep && ep.offset !== null ? { offset: ep.offset } : {} }));
}
async function loadSample() {
  $('#sampleBtn').disabled = true;
  try { const r = await fetch(sampleUrl); load('t32.exe', new Uint8Array(await r.arrayBuffer())); }
  catch (e) { showToast('Could not load the sample'); }
  finally { $('#sampleBtn').disabled = false; }
}
function initSuite() {
  const S = suite();
  const q = new URLSearchParams(location.search);
  if (S) {
    $('#caseBtn').hidden = false;
    $('#hexesBtn').hidden = false;
    const from = q.get('from');
    if (from) {
      S.receive('peek', from, { maxBytes: 256 << 20 })
        .then((h) => { if (h) { showToast(`Received ${fmtSize(h.bytes.length)} from ${h.fromName}`); openBytes(h.name, h.bytes); } })
        .catch((e) => showToast('Could not load the hand-off: ' + e.message));
      return;
    }
  }
  const sample = q.get('sample'), src = q.get('src');
  if (sample === 'arclight' || sample === 'kestrel') load('update.exe', buildArclight()); // Case 01's implant, generated here like Hexes does
  else if (sample) loadSample();
  else if (src) loadSrc(src);
}
// ?src=/path/to/file opens a file from this site, like Tessera's ?src=. Same-origin paths only;
// the production CSP (connect-src 'self') enforces that too.
async function loadSrc(src) {
  if (!/^\/(?!\/)/.test(src)) return showToast('?src= takes a path on this site, starting with /');
  try {
    const r = await fetch(src);
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    openBytes(decodeURIComponent(src.split('/').pop()) || 'file', new Uint8Array(await r.arrayBuffer()));
  } catch (e) { showToast('Could not open ' + src + ': ' + e.message); }
}
if (/^https?:$/.test(location.protocol)) {
  const sc = document.createElement('script');
  sc.src = '/assets/suite/handoff.js';
  sc.onload = initSuite;
  sc.onerror = initSuite; // not on jon.glass: no hand-offs, but ?sample=1 still works
  document.head.append(sc);
} else initSuite();

// ---------- wiring ----------
$('h1').append(h('span', { class: 'ver', title: 'Peek version' }, 'v' + VERSION));
$('#helpClose').addEventListener('click', () => $('#help').close());
$('#zipPwCancel').addEventListener('click', () => $('#zipPw').close());
$('#fileInput').addEventListener('change', (e) => { if (e.target.files[0]) loadFile(e.target.files[0]); e.target.value = ''; });
$('#sampleBtn').addEventListener('click', loadSample);
$('#caseBtn').addEventListener('click', sendToTessera);
$('#hexesBtn').addEventListener('click', sendToHexes);
$('#exportBtn').addEventListener('click', () => current && downloadJson());
$('#helpBtn').addEventListener('click', () => $('#help').showModal());
$('#themeBtn').addEventListener('click', () => {
  const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('peek-theme', next); } catch (e) {}
});
document.addEventListener('keydown', (e) => {
  if (e.target.matches('input, textarea')) return;
  if (e.key === '?') { e.preventDefault(); $('#help').showModal(); }
  if (e.key === 'o' && !e.metaKey && !e.ctrlKey) { e.preventDefault(); $('#fileInput').click(); }
});
let dragDepth = 0;
document.addEventListener('dragenter', (e) => { e.preventDefault(); if (++dragDepth === 1) document.body.classList.add('dragging'); });
document.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; document.body.classList.remove('dragging'); } });
document.addEventListener('dragover', (e) => e.preventDefault());
document.addEventListener('drop', (e) => { e.preventDefault(); dragDepth = 0; document.body.classList.remove('dragging'); const f = e.dataTransfer.files && e.dataTransfer.files[0]; if (f) loadFile(f); });
