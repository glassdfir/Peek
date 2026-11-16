// Parsing worker: receives { name, buffer }, replies { ok, pe, analysis } or { ok: false, error }.
import { parsePE, toJSON } from './pe.js';
import { analyze } from './analyze.js';

self.onmessage = (e) => {
  const { name, buffer } = e.data;
  try {
    const pe = parsePE(new Uint8Array(buffer));
    const analysis = analyze(pe, { fileName: name });
    self.postMessage({ ok: true, pe: toJSON(pe), analysis });
  } catch (err) {
    self.postMessage({ ok: false, error: (err && err.stack) || String(err) });
  }
};
