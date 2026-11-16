# ◉ Peek

A read-only PE (Portable Executable) header viewer for triage, in the spirit of
PE-bear and CFF Explorer, that runs entirely in the browser.

Drop in an EXE, DLL, SYS or any other Windows image and get headers, sections,
imports, exports, resources, debug info, signature presence, hashes and a list
of triage findings. Nothing is uploaded, nothing is executed.

## Run locally
    npm install
    npm run dev
Then open the address it prints (usually http://localhost:5173).

## Distribute it

    npm run build

Produces both:

- `dist-single/peek.html`: **one self-contained file**. Put it on a share, email
  it, keep it on a USB stick. Opens from disk with no install, no network, no
  admin rights. Works on a locked-down Windows host or a Mac.
- `dist/`: the website for any static host (GitHub Pages, an internal server).

`npm run build:single` builds just the single file.

## Command line

The same parser runs under Node, which is handy for batch triage:

    node bin/peek.mjs sample.exe              # summary + findings
    node bin/peek.mjs --json sample.exe       # full report as JSON
    node bin/peek.mjs --hashes *.exe          # sha256  imphash  rich-hash  name

## What it shows

- **Summary**: kind, architecture, subsystem, compile time, toolchain guess
  (MSVC generation from the Rich header, Go, Rust, MinGW, Delphi, .NET, …),
  version info, signer name, PDB path, entry point with its first bytes.
- **Hashes**: SHA-256, SHA-1, MD5, imphash (pefile-compatible), Rich header
  hash. One-click copy.
- **Findings**: packer section names, writable+executable sections, entry point
  outside any section or in the last section, high-entropy sections and
  resources, embedded executables in resources or overlay, zero / future /
  mismatched timestamps, signed-before-compiled, TLS callbacks, tiny import
  tables with LoadLibrary+GetProcAddress, injection-style API sets, native
  Nt*/Zw* calls, checksum mismatches, suspicious PDB paths, manifest
  autoElevate, and more. Findings are observations with a severity, not a
  verdict.
- **Headers**: DOS, COFF file header, optional header with decoded flags, data
  directories with the section each one lands in.
- **Sections**: addresses, sizes, permissions, entropy bar, MD5, flags.
- **Imports**: per-DLL with filter, delay-load and bound imports, ordinals
  resolved for oleaut32, ws2_32 and wsock32 (tables generated from pefile). **Exports** with forwarders. **Resources** with type,
  language, size, entropy and content sniffing; decoded VS_VERSIONINFO and
  manifest.
- **Debug & toolchain**: CodeView (RSDS/NB10) PDB path and GUID, REPRO hash,
  POGO, Rich header entries with tool names and checksum validity, TLS
  callbacks, CLR header, load config guard flags, relocation counts.
- **Signature & overlay**: Authenticode blob presence, digest algorithm, names
  found in the certificates, overlay size and content sniffing. The chain is
  not verified; use `signtool verify` or `Get-AuthenticodeSignature` for that.
- **JSON** export of the whole parse plus findings.

## On jon.glass: hand-offs to the other tools

When served from jon.glass, Peek loads the suite's shared `/assets/suite/handoff.js`
and gains two header buttons: **Add to case** sends the file to Tessera as an
evidence item with its hashes, the hashes as indicators, and the high and
medium findings as findings; **Open in Hexes** passes the bytes to the hex
viewer, positioned at the entry point. Opened with `?from=<tool>`, Peek
receives bytes from another tool the same way, and `?sample=1` loads the
sample on start. Hand-offs never leave the browser (same-origin localStorage)
and are unavailable in the single-file copy opened from disk.

Deployment: `.github/workflows/pages.yml` tests, builds and publishes `dist/`
to GitHub Pages on every push to `main`; with the custom domain on the user
site it appears at `https://jon.glass/<repo name>/`.

## Design notes

- `src/pe.js` is the parser: pure, bounds-checked, every directory parsed
  inside a try so a corrupt table degrades to a warning instead of a crash.
  Counts are capped and recursion depth-limited. Malware breaks headers on
  purpose; the viewer must survive that and say what it saw.
- `src/analyze.js` turns a parse into findings and a summary. Tune the packer
  section list and notable API groups there.
- `src/hash.js` is pure-JS MD5/SHA-1/SHA-256 so the same code runs in the
  single-file build, Node tests and CLI without WebCrypto.
- In the browser, parsing and hashing run in a Web Worker (`src/worker.js`,
  inlined into the single file) so a large installer does not freeze the
  page; the main thread is the fallback if the worker cannot start.
- Production builds carry a Content Security Policy that forbids remote
  scripts, connections and frames. The UI renders everything through text
  nodes and a test fails if an HTML sink ever appears in it.
- Reference values in the tests were cross-checked against pefile.
- `test/fuzz.mjs` mutates the corpus files (bit flips, truncation, bogus
  counts and pointers) and checks the parser never throws or stalls. A short
  pass runs under `npm test`; `node test/fuzz.mjs 20000` for a long one.

## Not yet

- .NET metadata tables, string tables, dialog/menu resources, hex view,
  disassembly, certificate chain validation, load config beyond guard flags.
- The test corpus has no driver, no signed file and no packed (UPX) file yet;
  those code paths were exercised only by hand. Add such samples to
  `test/corpus/` and pin their values.

## Tests

    npm test

Corpus (see `test/corpus/NOTICE.md` for provenance and licences):

- three small MSVC-built launchers from `pip`'s distlib (x86, x64, ARM64);
- DLLs with exports, a service EXE and a .NET assembly from Windows wheels
  on PyPI (`test/corpus/wheels/`);
- 219 proof-of-concept PEs from corkami/pocs (`test/corpus/corkami/`): tiny
  PEs with overlapping headers, zero SizeOfOptionalHeader, low alignment,
  folded imports, TLS tricks. All parse; the only rejections are the two
  files that are not PEs at all, and pefile rejects those too.

`node test/fuzz.mjs 20000` runs a long mutation-fuzz pass over the corpus.

## Licence

MIT. Test corpus files carry their own licences; see `test/corpus/NOTICE.md`.
