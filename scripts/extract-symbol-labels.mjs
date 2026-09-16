// Read-only bridge: Lumina hashes/addresses from a fixture DB, labels from ELF symbols.
// No annotation names or metadata are read from the fixture database.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function parseFunctionSymbols(text) {
  const symbols = new Map();
  for (const line of text.split('\n')) {
    const match = line.match(/^\s*\d+:\s+([\da-fA-F]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+(\d+)\s+(\S+)\s*$/);
    if (!match) continue;
    const [, address, size, , name] = match;
    // Zero-sized symbols do not independently establish the function extent.
    if (BigInt(size) === 0n) continue;
    const key = BigInt(`0x${address}`).toString(16);
    const at = symbols.get(key) ?? [];
    at.push({ name, size: BigInt(size) });
    symbols.set(key, at);
  }
  return symbols;
}

export function joinLabels(rows, symbols, identity) {
  const cases = [];
  const skipped = { no_symbol: 0, size_mismatch: 0 };
  const seen = new Set();
  for (const row of rows) {
    if (!/^[\da-f]{32}$/.test(row.key) || !/^[\da-f]+$/.test(row.address)
        || !/^[1-9]\d*$/.test(row.size)) throw new Error('invalid fixture key/address/size');
    if (seen.has(row.key)) throw new Error('duplicate fixture key; resolve ambiguity before evaluation');
    seen.add(row.key);
    const address = BigInt(`0x${row.address}`).toString(16);
    const candidates = symbols.get(address);
    if (!candidates) { skipped.no_symbol++; continue; }
    const names = [...new Set(candidates.filter(s => s.size === BigInt(row.size)).map(s => s.name))].sort();
    if (!names.length) { skipped.size_mismatch++; continue; }
    if (cases.length === 65536) throw new Error('label case bound exceeded');
    cases.push({
      ...identity,
      case_id: `${identity.binary_md5}:${row.key}`,
      key: row.key,
      address: `0x${address}`,
      size_bytes: row.size,
      expected_names: names,
    });
  }
  return { cases, skipped };
}

export function extract(database, binary, family, partition) {
  if (!family.trim() || !['development', 'test'].includes(partition)) {
    throw new Error('nonempty family and partition development|test required');
  }
  database = resolve(database);
  binary = resolve(binary);
  for (const path of [database, binary]) {
    if (statSync(path).size > 256 * 1024 * 1024) throw new Error('fixture exceeds 256 MiB input bound');
  }
  if (existsSync(`${database}-wal`) || existsSync(`${database}-journal`)) {
    throw new Error('fixture has a WAL/journal; supply a consistent offline snapshot');
  }
  const digest = path => createHash('sha256').update(readFileSync(path)).digest('hex');
  const databaseDigest = digest(database);
  const sql = query => JSON.parse(execFileSync('sqlite3', ['-readonly', '-json', database, query], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  }).trim() || '[]');
  const bytes = readFileSync(binary);
  const md5 = createHash('md5').update(bytes).digest('hex');
  const binaryDigest = createHash('sha256').update(bytes).digest('hex');
  const inputs = sql('SELECT DISTINCT lower(hex(hash)) AS md5 FROM inputs');
  if (inputs.length !== 1 || inputs[0].md5 !== md5) {
    throw new Error('fixture input identity is not exactly this binary; refuse address join');
  }
  const orphaned = sql('SELECT count(*) AS count FROM funcs f JOIN calcrel_hash c ON c.fk_func=f.id WHERE NOT EXISTS (SELECT 1 FROM history h JOIN idbs d ON d.id=h.fk_idb JOIN inputs i ON i.id=d.fk_input WHERE h.fk_func=f.id)');
  if (orphaned[0]?.count !== 0) throw new Error('function hashes lack history links to the verified input');
  const symbols = parseFunctionSymbols(execFileSync('llvm-readelf', ['--symbols', binary], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  }));
  const rows = sql('SELECT lower(hex(h.hash)) AS key, printf("%x", f.ea) AS address, cast(f.size as text) AS size FROM funcs f JOIN calcrel_hash h ON h.fk_func=f.id ORDER BY f.ea, h.hash');
  const result = joinLabels(rows, symbols, {
    family, partition, binary_md5: md5,
    binary_sha256: binaryDigest,
    fixture_sha256: databaseDigest,
    provenance: {
      binary: resolve(binary), fixture_database: resolve(database),
      labels: 'ELF STT_FUNC symbols with exact address and size; aliases retained',
      keys: 'fixture calcrel_hash joined to funcs; history links and single input MD5 verified',
    },
  });
  if (databaseDigest !== digest(database)) throw new Error('fixture database changed during extraction');
  if (binaryDigest !== digest(binary)) throw new Error('binary changed during extraction');
  return { ...result, source_rows: rows.length };
}

export function extractDirectory(root, family, partition) {
  const cases = [], summaries = [];
  for (const file of readdirSync(root).filter(n => n.endsWith('.sqlite3')).sort()) {
    const stem = file.slice(0, -8), binary = resolve(root, `${stem}.elf`);
    if (!existsSync(binary)) continue;
    const result = extract(resolve(root, file), binary, family, partition);
    if (cases.length + result.cases.length > 65536) throw new Error('label case bound exceeded');
    for (const row of result.cases) cases.push(row);
    summaries.push({ fixture: stem, source_rows: result.source_rows, labeled: result.cases.length, skipped: result.skipped });
  }
  if (!summaries.length) throw new Error('no SQLite/ELF fixture pairs');
  return { cases, summaries };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 4) throw new Error('usage: node scripts/extract-symbol-labels.mjs FIXTURE.sqlite3 BINARY.elf FAMILY development|test OR --directory ROOT FAMILY development|test');
    const result = args[0] === '--directory' ? extractDirectory(...args.slice(1)) : extract(...args);
    for (const row of result.cases) console.log(JSON.stringify(row));
    console.error(JSON.stringify({ source_rows: result.source_rows, labeled: result.cases.length, skipped: result.skipped, fixtures: result.summaries }));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
