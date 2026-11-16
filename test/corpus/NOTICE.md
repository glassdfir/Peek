# Test corpus provenance

Binaries here are inputs for the parser tests only. None are executed.

- `t32.exe`, `w64.exe`, `t64-arm.exe`: launcher stubs shipped inside pip's
  vendored `distlib` (simple_launcher, BSD-licensed). Clean MSVC builds for
  x86, x64 and ARM64.
- `wheels/markupsafe_speedups.pyd`: from the MarkupSafe 3.0.4 win_amd64 wheel
  (BSD-3-Clause). A DLL with one export.
- `wheels/pywintypes312.dll`, `wheels/pythonservice.exe`: from the pywin32 312
  win_amd64 wheel (PSF-style licence, see the wheel's License.txt). A DLL
  with many exports, and a small service host EXE.
- `wheels/Python.Runtime.dll`: from the pythonnet 3.2.1 wheel (MIT). A .NET
  assembly, for the CLR header path.
- `corkami/*`: proof-of-concept PEs from Ange Albertini's
  https://github.com/corkami/pocs (BSD licence, 2009-2013), every binary PoC
  up to 64 KB. Deliberately strange but Windows-loadable files: tiny PEs,
  overlapping headers, zero SizeOfOptionalHeader, odd alignments, folded
  imports, TLS tricks. The parser must survive all of them; `corkami.test.mjs`
  checks that and pins a few of their values.
