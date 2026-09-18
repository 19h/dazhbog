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
    let start = source.indexOf(`        function ${name}(`);
    if (start < 0) start = source.indexOf(`        async function ${name}(`);
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
    // Like a browser, replacing the URL with a hash-less path clears the hash.
    history: { replaceState(_state, _title, url) { if (typeof url === 'string' && !url.includes('#')) location.value = ''; } },
    document: { getElementById() { return el.modalKey; } },
    detailRequestGeneration: 0, hashRequestGeneration: 0, currentDetailBinaryMd5: null,
    currentSearchMode: 'functions', currentQuery: '', currentPage: 1,
    compareKeys: [], compareMode: 'summary', compareShowAll: false,
    currentBinaryCompareMode: 'all', currentBinaryComparePage: 1,
    currentBinaryCompareQuery: '', currentSemanticNeighborLimit: 8,
    currentSemanticNeighborStrictFamily: false,
    currentRecentKind: 'functions', currentRecentLimit: 100, currentRecentOrder: 'last_seen',
    RECENT_PAGE_DEFAULT_LIMIT: 100, RECENT_PAGE_LIMITS: [25, 50, 100, 200], currentHits: [], copiedKeyHex: null,
    recentOpen: false, recentPageGeneration: 0, currentRecentData: null,
    isDetailPageOpen: () => true, isComparePageOpen: () => false,
    isRecentPageOpen() { return context.recentOpen; },
    setSearchMode() {}, hideFullPages() { context.recentOpen = false; },
    activateFullPage(kind) { context.recentOpen = kind === 'recent'; }, showDashboard() {},
    restorePrimarySurface() { context.recentOpen = false; },
    binaryNetReset() {},
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
// Recent-submission page: request shape, hash round trip, stale-response guard
// and deep-link restoration without a search.
for (const name of ['recentRequestUrl', 'recentPageHref', 'recentOrderLabel', 'recentBinaryTimestamp',
    'recentFunctionRowHtml', 'recentBinaryRowHtml', 'recentPageControlsHtml', 'showRecentPage',
    'closeRecentPage', 'loadRecentPage', 'renderRecentPage']) {
    run(shipped(name));
}
el.recentPage = {}; el.recentPageTitle = {}; el.recentPageBody = {};
el.recentPageStatus = { classList: { toggle() {} } };
context.document.getElementById = id => id === 'recent-page-status' ? el.recentPageStatus : el.modalKey;
context.performance = { now: () => 0 };
context.fmtBytes = String;
context.isDetailPageOpen = () => false;
run('showRecentPage("binaries", 50, "first_seen")');
assert.equal(requests.at(-1).url, '/api/recent/binaries?limit=50&order=first_seen');
assert.ok(run('isRecentPageOpen()'));
assert.deepEqual([run('parseHash().r'), run('parseHash().rn'), run('parseHash().ro')], ['binaries', 50, 'first_seen']);
assert.equal(run('recentPageHref("functions", 100, "last_seen")'), '#r=functions&rn=100');
assert.equal(run('recentPageHref("binaries", 25, "first_seen")'), '#r=binaries&rn=25&ro=first_seen');
const staleBinaries = requests.at(-1);
run('showRecentPage("functions", 25)');
assert.equal(requests.at(-1).url, '/api/recent/functions?limit=25');
assert.equal(run('parseHash().r'), 'functions');
assert.equal(run('parseHash().ro'), 'last_seen');
reply(staleBinaries, { results: [{ md5_hex: b, basename: 'stale.bin', display_name: 'stale.bin' }], limit: 50, order: 'first_seen' });
await settle();
assert.ok(!String(el.recentPageBody.innerHTML).includes('stale.bin'), 'stale binaries reply must not replace the functions page');
reply(requests.at(-1), { results: [{ key_hex: key, func_name: 'fresh_function', ts: 1, popularity: 2, data_size: 3, segment: 1,
    binaries: [{ md5_hex: a, short_id: a.slice(0, 8), basename: 'app.bin', display_name: 'app.bin' }] }],
    limit: 25, scanned_records: 1, invalid_records: 0, truncated: false, scan_bound: 4096 });
await settle();
assert.ok(String(el.recentPageBody.innerHTML).includes('fresh_function'));
assert.ok(String(el.recentPageBody.innerHTML).includes('app.bin'));
assert.ok(String(el.recentPageBody.innerHTML).includes(`openRecentFunction('${key}')`));
// A user-supplied name is escaped in every rendered context. The shipped
// signature renderer escapes its own output; the double here stands in for it.
context.renderCompactSignatureText = context.esc;
const hostile = run('recentFunctionRowHtml({ key_hex: key, func_name: "<img src=x onerror=alert(1)>", ts: 1, binaries: [{ md5_hex: a, short_id: "x", basename: "<b>.bin", display_name: "d" }] }, 0, true)');
assert.ok(!hostile.includes('<img') && !hostile.includes('<b>'));
assert.ok(hostile.includes('&lt;img') && hostile.includes('&lt;b&gt;.bin'));
const hostileBinary = run('recentBinaryRowHtml({ md5_hex: b, basename: "<s>.exe", display_name: "<s>.exe", hostname: "<i>host", function_count: 1, obs_count: 1, last_seen_ts: 1 }, 0, false, "last_seen")');
assert.ok(!hostileBinary.includes('<s>') && !hostileBinary.includes('<i>'));
assert.ok(hostileBinary.includes(`openRecentBinary('${b}')`));
// A deep link restores the page from the hash alone, without a search request.
location.hash = 'r=binaries&rn=200';
run('applyHashState(parseHash())');
assert.equal(requests.at(-1).url, '/api/recent/binaries?limit=200&order=last_seen');
assert.equal(run('currentRecentLimit'), 200);
assert.equal(run('currentRecentKind'), 'binaries');
const beforeClose = requests.length;
run('closeRecentPage()');
assert.ok(!run('isRecentPageOpen()'));
assert.equal(run('parseHash().r'), '');
assert.equal(requests.length, beforeClose, 'closing the recent page without a query must not search');
console.log('Browser context: syntax, identity, deep links, neighbors, stale responses, coverage denominators and recent feed passed.');
