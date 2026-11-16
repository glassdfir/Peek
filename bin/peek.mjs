#!/usr/bin/env node
// Command-line front end: same parser as the web app.
//   node bin/peek.mjs <file.exe>            summary + findings
//   node bin/peek.mjs --json <file.exe>     full report as JSON
//   node bin/peek.mjs --hashes <files...>   one line per file: sha256 imphash rich name
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { parsePE, toJSON, hex } from '../src/pe.js';
import { analyze } from '../src/analyze.js';
import { VERSION } from '../src/version.js';

const args = process.argv.slice(2);
const flag = (f) => { const i = args.indexOf(f); if (i >= 0) { args.splice(i, 1); return true; } return false; };
if (flag('--version') || flag('-v')) { console.log(`peek ${VERSION}`); process.exit(0); }
const json = flag('--json'), hashesOnly = flag('--hashes');
if (!args.length) { console.error('usage: peek [--json|--hashes] <file>...'); process.exit(2); }

for (const file of args) {
  const bytes = new Uint8Array(readFileSync(file));
  const pe = parsePE(bytes);
  const name = basename(file);
  const a = analyze(pe, { fileName: name });
  if (hashesOnly) { console.log([pe.hashes.sha256, pe.hashes.imphash || '-', pe.hashes.richHash || '-', name].join('  ')); continue; }
  if (json) { console.log(JSON.stringify({ file: name, generator: `peek ${VERSION}`, note: 'Findings are observations, not verdicts. Signature data is presence and names only; the chain was not verified.', ...toJSON(pe), analysis: a }, null, 2)); continue; }
  const s = a.summary;
  console.log(`\n${name}  (${bytes.length} bytes)`);
  if (pe.errors.length) { for (const e of pe.errors) console.log('  !! ' + e); continue; }
  console.log(`  ${s.kind} · ${s.machine} · ${s.format} · ${s.subsystem}`);
  console.log(`  compiled ${s.compiled || '(none)'} · linker ${s.linker} · ${s.compiler || 'unknown toolchain'}${s.packer ? ' · packer: ' + s.packer : ''}`);
  if (s.description || s.company) console.log(`  "${s.description || ''}" ${s.company ? 'by ' + s.company : ''} ${s.version ? 'v' + s.version : ''} ${s.originalFilename ? '(' + s.originalFilename + ')' : ''}`);
  console.log(`  ${s.signed ? 'signed' + (s.signer ? ' by ' + s.signer : '') : 'unsigned'} · ASLR ${s.aslr ? 'on' : 'off'} · DEP ${s.dep ? 'on' : 'off'} · CFG ${s.cfg ? 'on' : 'off'}`);
  if (s.pdb) console.log(`  pdb ${s.pdb}`);
  console.log(`  sha256  ${pe.hashes.sha256}\n  sha1    ${pe.hashes.sha1}\n  md5     ${pe.hashes.md5}\n  imphash ${pe.hashes.imphash || '-'}\n  rich    ${pe.hashes.richHash || '-'}`);
  console.log(`  entry ${hex(pe.entryPoint.rva)} in ${pe.entryPoint.section || '(no section)'}`);
  console.log('  sections');
  for (const sec of pe.sections) console.log(`    ${sec.displayName.padEnd(10)} va ${hex(sec.virtualAddress, 8)} vsize ${hex(sec.virtualSize, 8)} raw ${hex(sec.pointerToRawData, 8)}+${hex(sec.sizeOfRawData, 8)}  ent ${sec.entropy.toFixed(2)}  ${sec.readable ? 'R' : '-'}${sec.writable ? 'W' : '-'}${sec.executable ? 'X' : '-'}`);
  console.log(`  imports ${s.importedApis} from ${s.importedDlls} DLLs: ${[...pe.imports, ...pe.delayImports].map((d) => d.name + (d.delay ? '*' : '')).join(', ')}`);
  if (pe.exports) console.log(`  exports ${pe.exports.functions.length} (${pe.exports.name || '?'})`);
  if (a.notableImports.length) { console.log('  notable imports'); for (const g of a.notableImports) console.log(`    ${g.group}: ${g.apis.join(', ')}`); }
  console.log(`  findings: ${a.counts.high} high, ${a.counts.medium} medium, ${a.counts.low} low, ${a.counts.info} info`);
  for (const f of a.findings) console.log(`    [${f.severity.padEnd(6)}] ${f.title}${f.detail ? ' — ' + f.detail : ''}`);
}
