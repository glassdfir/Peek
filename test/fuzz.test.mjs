// Short mutation-fuzz pass as part of the normal test run. For a long run use: node test/fuzz.mjs 20000
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fuzzOnce, corpusFiles } from './fuzz.mjs';

test('parser survives 200 mutations of every corpus file without throwing or stalling', () => {
  const failures = [];
  for (const f of corpusFiles()) {
    for (let i = 0; i < 200; i++) {
      const res = fuzzOnce(f.bytes, 1000 + i * 31, { budgetMs: 1000 });
      if (!res.ok) failures.push(`${f.name} seed=${res.seed} ops=${res.ops.join(',')}: ${res.error.split('\n')[0]}`);
    }
  }
  assert.deepEqual(failures, []);
});
