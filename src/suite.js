// What Peek hands to Tessera (the suite's case notebook) as a 'case' hand-off:
// the file as an evidence item, its hashes as indicators, and the high and
// medium findings as findings with a confidence. Pure, so it is unit-tested.
// origin (optional): { archive, path, encryption } when the file was extracted from a ZIP.
export function caseItems({ name, size, pe, analysis, origin }) {
  const s = (analysis && analysis.summary) || {};
  const h = pe.hashes || {};
  const about = [s.kind, s.machine, s.compiled ? 'compiled ' + s.compiled : null, s.compiler, s.signed ? 'signed' + (s.signer ? ' by ' + s.signer : '') : 'unsigned']
    .filter(Boolean).join(', ');
  const from = origin ? ` Extracted from ${origin.archive} (entry ${origin.path}${origin.encryption && origin.encryption !== 'none' ? ', ' + origin.encryption : ''}); hashes are of the extracted file.` : '';
  return {
    evidence: [{ name, sha256: h.sha256 || '', md5: h.md5 || '', size: String(size), source: origin ? `${origin.archive} › ${origin.path}` : '', note: `Examined in Peek: ${about}. imphash ${h.imphash || '-'}.${from}` }],
    indicators: [['sha256', h.sha256], ['sha1', h.sha1], ['md5', h.md5]].filter(([, v]) => v).map(([type, value]) => ({ type, value, note: name })),
    findings: ((analysis && analysis.findings) || [])
      .filter((f) => f.severity === 'high' || f.severity === 'medium')
      .map((f) => ({ title: `${f.title} (${name})`, detail: `${f.detail ? f.detail + ' ' : ''}File SHA-256 ${h.sha256 || '?'}.`, confidence: f.severity === 'high' ? 'likely' : 'possible' })),
  };
}
