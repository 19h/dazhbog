// Execute the shipped browser functions with deterministic network/DOM doubles.
// No dependencies or generated files. Run: node scripts/test-browser-context.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../src/api/http/templates.rs', import.meta.url), 'utf8');
const scripts = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)];
assert.ok(scripts.length > 0, 'shipped inline script exists');
for (const match of scripts) new vm.Script(match[1]);
function shipped(name) {
    const start = source.indexOf(`        function ${name}(`);
    assert.ok(start >= 0, name);
    const end = source.indexOf('\n        }', start);
    return source.slice(start, end + '\n        }'.length);
}
const requests = [];
const rendered = [];
const el = { modalTitle: {}, modalKey: {}, modalBody: {}, q: {} };
const location = {
    pathname: '/', value: '',
    get hash() { return this.value; },
    set hash(value) { this.value = value ? '#' + value.replace(/^#/, '') : ''; },
};
const context = vm.createContext({
    URLSearchParams, encodeURIComponent, setTimeout, console, el,
    window: { location },
    history: { replaceState() {} },
    document: { getElementById() { return el.modalKey; } },
    detailRequestGeneration: 0, hashRequestGeneration: 0, currentDetailBinaryMd5: null,
    currentSearchMode: 'functions', currentQuery: '', currentPage: 1,
    compareKeys: [], compareMode: 'summary', compareShowAll: false,
    currentBinaryCompareMode: 'all', currentBinaryComparePage: 1,
    currentBinaryCompareQuery: '', currentSemanticNeighborLimit: 8,
    currentSemanticNeighborStrictFamily: false,
    isDetailPageOpen: () => true, isComparePageOpen: () => false,
    setSearchMode() {}, hideFullPages() {}, activateFullPage() {}, showDashboard() {},
    esc: String,
    renderFunctionDetail: data => rendered.push(data),
    fetch(url) {
        return new Promise((resolve, reject) => requests.push({ url, resolve, reject }));
    },
});
for (const name of ['parseHash', 'updateHash', 'syncHashWithUi', 'applyHashState',
    'showFunctionDetail', 'functionDetailHref', 'semanticNeighborRequestSig', 'ensureSemanticNeighborsLoaded',
    'renderSemanticNeighborSection', 'renderBinaryCompareItem', 'exportBinaryCompareCsv', 'exportBinaryCompareMarkdown']) {
    vm.runInContext(shipped(name), context);
}
const run = code => vm.runInContext(code, context);
const settle = () => new Promise(resolve => setImmediate(resolve));
const reply = (request, body) => request.resolve({ ok: true, json: async () => body });
const a = '01'.repeat(16), b = '02'.repeat(16), key = '1'.padStart(32, '0');

context.a = a; context.b = b; context.key = key;
run('showFunctionDetail(key, null, true, a)');
assert.equal(requests[0].url, `/api/function/${key}?md5=${a}`);
assert.equal(run('parseHash().b'), a);
assert.equal(run('parseHash().f'), key);
assert.equal(new URLSearchParams(run('functionDetailHref(key)').slice(1)).get('b'), a);
const firstSig = run('semanticNeighborRequestSig(key)');
run('showFunctionDetail(key, null, true, b)');
assert.notEqual(run('semanticNeighborRequestSig(key)'), firstSig);
reply(requests[1], { key_hex: key, binary_md5: b });
await settle();
reply(requests[0], { key_hex: key, binary_md5: a });
await settle();
assert.equal(rendered.length, 1, 'stale binary A response must not replace B');
assert.equal(rendered[0].binary_md5, b);

run('ensureSemanticNeighborsLoaded(key)');
assert.ok(requests[2].url.endsWith(`&md5=${b}`));
run('showFunctionDetail(key, null, false, a)');
reply(requests[2], { results: [{ key_hex: key, func_name: 'stale neighbor' }] });
await settle();
assert.equal(run('currentSemanticNeighbors'), null);
run('showFunctionDetail(key, null, false, b)');
requests[3].reject(new Error('stale failure'));
await settle();
assert.ok(!String(el.modalBody.innerHTML).includes('stale failure'));

// Restore a deep link for the same key but a different binary, then clear context
// on a global search result. Each path must make a distinct request.
context.saved = { m: 'functions', f: key, b: a };
run('applyHashState(saved)');
assert.equal(requests.at(-1).url, `/api/function/${key}?md5=${a}`);
run('showFunctionDetail(key)');
assert.equal(requests.at(-1).url, `/api/function/${key}`);
assert.equal(run('parseHash().b'), '');
assert.equal(run('currentDetailBinaryMd5'), null);
let finishSearch;
context.runSearch = () => new Promise(resolve => { finishSearch = resolve; });
context.saved.q = 'delayed search';
run('applyHashState(saved)');
run('showFunctionDetail(key, null, false, b)');
const requestCount = requests.length;
finishSearch();
await settle();
assert.equal(requests.length, requestCount, 'stale search completion must not reopen the previous context');
context.renderCompactSignatureText = String;
context.fmtRelativeTs = String;
context.renderSemanticNeighborRationale = () => '';
context.event = { preventDefault() {} };
run('currentSemanticNeighbors = [{ key_hex: key, func_name: "neighbor" }]; currentSemanticNeighborLoadedSig = semanticNeighborRequestSig(key); currentSemanticNeighborLoadingSig = null;');
const html = run('renderSemanticNeighborSection()');
const click = html.match(/<a class="neighbor-card-link"[^>]* onclick="([^"]*)"/)[1];
run(click);
assert.equal(requests.at(-1).url, `/api/function/${key}?md5=${b}`);
// A shared key carries two separately navigable variants, including in exports.
context.fmt = String;
context.esc = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
context.comparison = {
    left: { md5_hex: a, basename: 'left.bin' }, right: { md5_hex: b, basename: 'right.bin' },
    active_bucket: 'Shared', active_bucket_items: [{ key_hex: key, left_member: true, right_member: true,
        left: { name: 'left <annotation>', ts: 10, richness_score: 1, matches_last_observation: true },
        right: { name: 'right "annotation"', ts: 20, richness_score: 2, matches_last_observation: false },
        annotation_relation: 'different', changed_metadata_keys: [42], rarity_score: 2 }],
};
const pairHtml = run('renderBinaryCompareItem(comparison.active_bucket_items[0], comparison)');
assert.ok(pairHtml.includes('left &lt;annotation&gt;'));
assert.ok(pairHtml.includes('right &quot;annotation&quot;'));
const sideClicks = [...pairHtml.matchAll(/onclick="([^"]*)"/g)].map(m => m[1]);
assert.equal(sideClicks.length, 2);
run(sideClicks[0]); assert.equal(requests.at(-1).url, `/api/function/${key}?md5=${a}`);
run(sideClicks[1]); assert.equal(requests.at(-1).url, `/api/function/${key}?md5=${b}`);
const exports = [];
context.Blob = Blob;
context.URL = { createObjectURL(blob) { exports.push(blob); return 'blob:test'; }, revokeObjectURL() {} };
context.document.createElement = () => ({ click() {}, remove() {} });
context.document.body = { appendChild() {} };
run('currentBinaryCompareData = comparison; exportBinaryCompareCsv(); exportBinaryCompareMarkdown();');
const csv = await exports[0].text(), markdown = await exports[1].text();
assert.ok(csv.includes('"left_name","right_name"'));
assert.ok(csv.includes('"left <annotation>","right ""annotation"""'));
assert.ok(csv.includes('"10","20","true","false","different","42"'));
assert.ok(markdown.includes('left <annotation>') && markdown.includes('right \\"annotation\\"'));
run(shipped('renderCoverageStrip'));
assert.ok(run('renderCoverageStrip({function_count: 100, typed_functions: 100})').includes('not computed'));
context.coverageBinary = { function_count: 100, typed_functions: 100,
    coverage: { function_count: 2, typed_functions: 1, commented_functions: 0, switch_functions: 0 } };
assert.ok(run('renderCoverageStrip(coverageBinary)').includes('width:50%'));
const zeroCoverage = run('renderCoverageStrip(coverageBinary, {function_count: 0, typed_functions: 0})');
assert.ok(zeroCoverage.includes('width:0%'));
assert.ok(!zeroCoverage.includes('width:50%') && !zeroCoverage.includes('width:100%'));
console.log('Browser context: syntax, identity, deep links, neighbors, stale responses and coverage denominators passed.');
