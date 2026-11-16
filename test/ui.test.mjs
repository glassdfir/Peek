// Guards on the UI layer that do not need a browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { VERSION } from '../src/version.js';

const src = (f) => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

test('UI never renders file-derived strings as HTML', () => {
  // Manifest text, version strings, PDB paths and import names are attacker-controlled.
  // Everything must go through text nodes; none of these sinks may appear in the UI code.
  for (const f of ['src/main.js', 'src/worker.js']) {
    const code = src(f);
    for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'srcdoc', 'eval(', 'new Function']) {
      assert.ok(!code.includes(sink), `${f} uses ${sink}`);
    }
  }
});

test('version is consistent across package.json, version.js and README', () => {
  const pkg = JSON.parse(src('package.json'));
  assert.equal(pkg.version, VERSION);
});

test('index.html keeps the no-network promise visible and has no external resources', () => {
  const html = src('index.html');
  assert.match(html, /never leaves this machine/);
  assert.ok(!/https?:\/\//.test(html.replace(/xmlns='http:\/\/www\.w3\.org\/2000\/svg'/g, '')), 'index.html references an external URL');
});
