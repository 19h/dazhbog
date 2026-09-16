import assert from 'node:assert/strict';
import test from 'node:test';
import { joinLabels, parseFunctionSymbols } from './extract-symbol-labels.mjs';

test('only defined, sized function symbols supply labels; exact address/extent and aliases survive', () => {
  const symbols = parseFunctionSymbols(`
  1: 0020000000000001 16 FUNC GLOBAL DEFAULT 3 first
  2: 0020000000000001 16 FUNC WEAK DEFAULT 3 alias
  3: 0020000000000001 12 FUNC GLOBAL DEFAULT 3 overlapping
  4: 0020000000000002 16 FUNC GLOBAL DEFAULT UND imported
  5: 0020000000000003 16 OBJECT GLOBAL DEFAULT 3 object
  6: 0020000000000004 0 FUNC LOCAL DEFAULT 3 unknown_extent
  7: 0020000000000005 16 NOTYPE GLOBAL DEFAULT 3 label
  8: 0020000000000006 12 FUNC GLOBAL DEFAULT 3 wrong_extent
  `);
  const rows = Array.from({ length: 6 }, (_, i) => ({
    key: (i + 1).toString(16).padStart(32, '0'),
    address: (0x20000000000001n + BigInt(i)).toString(16), size: '16',
  }));
  const { cases, skipped } = joinLabels(rows, symbols, { binary_md5: '0'.repeat(32) });
  assert.equal(cases.length, 1);
  assert.deepEqual(cases[0].expected_names, ['alias', 'first']);
  assert.equal(cases[0].address, '0x20000000000001');
  assert.deepEqual(skipped, { no_symbol: 4, size_mismatch: 1 });
});

test('malformed fixture identities fail closed', () => {
  assert.throws(() => joinLabels([{ key: 'bad', address: '0', size: '0' }], new Map(), {}));
  const row = { key: '0'.repeat(32), address: '123', size: '10' };
  assert.throws(() => joinLabels([row, row], new Map(), {}), /duplicate/);
});
