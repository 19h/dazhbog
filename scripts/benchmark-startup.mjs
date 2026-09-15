// Node.js 20+. Uses an offline prepared copy, loopback listeners and owned children.
// Usage: node scripts/benchmark-startup.mjs SERVER CONFIG HTTP_PORT RPC_PORT [RUNS] [warm|purge]
import { spawn, spawnSync } from 'node:child_process';
import { createServer, createConnection } from 'node:net';
import { get } from 'node:http';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';

const [server, config, httpArg, rpcArg, runArg = '20', cache = 'warm', ...extra] = process.argv.slice(2);
const httpPort = Number(httpArg), rpcPort = Number(rpcArg), runs = Number(runArg);
if (!server || !config || extra.length || ![httpPort, rpcPort].every(p => Number.isInteger(p) && p > 0 && p < 65536)
    || httpPort === rpcPort || !Number.isInteger(runs) || runs < 1 || runs > 100 || !['warm', 'purge'].includes(cache)) {
  throw new Error('usage: benchmark-startup.mjs SERVER CONFIG HTTP_PORT RPC_PORT [1..100] [warm|purge]');
}

async function assertFree(port) {
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(port, '127.0.0.1', resolve);
  });
  await new Promise((resolve, reject) => probe.close(e => e ? reject(e) : resolve()));
}

function json(path) {
  return new Promise((resolve, reject) => {
    const req = get({ hostname: '127.0.0.1', port: httpPort, path, agent: false, headers: { Connection: 'close' } }, res => {
      const chunks = [];
      let size = 0;
      res.on('data', chunk => {
        size += chunk.length;
        if (size > 16 * 1024 * 1024) { req.destroy(new Error('HTTP response exceeds 16 MiB')); return; }
        chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode !== 200) { reject(new Error(`${path}: HTTP ${res.statusCode}`)); return; }
        try { resolve(JSON.parse(Buffer.concat(chunks))); } catch (e) { reject(e); }
      });
    });
    req.setTimeout(30_000, () => req.destroy(new Error(`${path}: timeout`)));
    req.on('error', reject);
  });
}

function exchange(socket, type, payload, lumina = false) {
  const frame = Buffer.alloc(5 + payload.length);
  frame.writeUInt32BE(payload.length + (lumina ? 0 : 1));
  frame[4] = type;
  payload.copy(frame, 5);
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const finish = (error, value) => {
      socket.off('data', data); socket.off('error', fail); socket.off('end', end);
      error ? reject(error) : resolve(value);
    };
    const fail = error => finish(error), end = () => fail(new Error('RPC ended before a complete frame'));
    const data = chunk => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length < 4) return;
      const length = buffered.readUInt32BE(0) + (lumina ? 1 : 0);
      if (length < 1 || length > 16 * 1024 * 1024) { fail(new Error('invalid RPC frame length')); return; }
      if (buffered.length >= length + 4) finish(null, buffered.subarray(4, length + 4));
    };
    socket.on('data', data); socket.once('error', fail); socket.once('end', end);
    socket.write(frame);
  });
}

async function rpc(key) {
  const socket = createConnection({ host: '127.0.0.1', port: rpcPort });
  socket.setTimeout(30_000, () => socket.destroy(new Error('RPC timeout')));
  try {
    await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
    const hello = Buffer.from('0600000005000000677565737400000000', 'hex');
    if ((await exchange(socket, 1, hello))[0] !== 2) throw new Error('RPC hello failed');
    const payload = Buffer.alloc(20);
    payload.writeUInt32LE(1);
    Buffer.from(key, 'hex').reverse().copy(payload, 4);
    const response = await exchange(socket, 0x10, payload);
    if (response.length < 13 || response[0] !== 0x11 || response.readUInt32LE(1) !== 1
        || response.readUInt32LE(5) !== 0 || response.readUInt32LE(9) !== 1) throw new Error('RPC pull did not return the requested function');
  } finally { socket.destroy(); }
  const lumina = createConnection({ host: '127.0.0.1', port: rpcPort });
  lumina.setTimeout(30_000, () => lumina.destroy(new Error('Lumina timeout')));
  try {
    await new Promise((resolve, reject) => { lumina.once('connect', resolve); lumina.once('error', reject); });
    // v3, empty key, six-byte license, record convention 1, guest, empty password.
    const hello = Buffer.from('03000000000000000167756573740000', 'hex');
    if ((await exchange(lumina, 0x0d, hello, true))[0] !== 0x0a) throw new Error('Lumina hello failed');
  } finally { lumina.destroy(); }
}

const samples = [];
for (let run = 0; run < runs; run++) {
  await Promise.all([assertFree(httpPort), assertFree(rpcPort)]);
  if (cache === 'purge') {
    const result = spawnSync('/usr/sbin/purge', [], { encoding: 'utf8' });
    if (result.error || result.status !== 0) throw new Error(`cache purge failed: ${result.error ?? result.stderr}`);
  }
  const start = performance.now();
  let logs = '', spawnError;
  const child = spawn(server, [config], { env: { ...process.env, RUST_LOG: 'dazhbog=info' }, stdio: ['ignore', 'pipe', 'pipe'] });
  const ended = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  child.once('error', error => { spawnError = error; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { logs = (logs + chunk).slice(-16_384); });
  try {
    let ready = false;
    while (performance.now() - start < 30_000) {
      if (spawnError) throw spawnError;
      if (child.exitCode !== null || child.signalCode !== null) throw new Error(`server exited: ${logs}`);
      if (!logs.includes(`http listening on 127.0.0.1:${httpPort}`)
          || !logs.includes(`listening on 127.0.0.1:${rpcPort}`)) {
        await delay(10); continue;
      }
      try { await json('/api/metrics'); ready = true; break; } catch { await delay(10); }
    }
    if (!ready) throw new Error(`startup timeout: ${logs}`);
    const readyS = (performance.now() - start) / 1000;
    const phaseS = {};
    const timed = async (name, promise) => {
      const begin = performance.now();
      const value = await promise;
      phaseS[name] = (performance.now() - begin) / 1000;
      return value;
    };
    const search = await timed('search', json('/api/search?q=parse&per_page=24'));
    const hit = search.results.find(item => item.binaries?.length);
    if (!hit) throw new Error('benchmark requires a parse search hit with a binary association');
    const key = hit.key_hex, md5 = hit.binaries[0].md5_hex;
    const [, neighbors] = await Promise.all([
      timed('detail', json(`/api/function/${key}`)),
      timed('neighbors', json(`/api/function/${key}/neighbors?limit=8`)),
      timed('binary', json(`/api/binary/${md5}`)),
      timed('rpc', rpc(key)),
    ]);
    const result = { run: run + 1, cache_condition: cache === 'purge' ? 'OS-cache-purge' : 'warm-uncontrolled',
      ready_s: readyS, useful_s: (performance.now() - start) / 1000,
      search_hits: search.results.length, neighbor_hits: neighbors.results.length, phase_s: phaseS,
      open_elapsed_s: Object.fromEntries([...logs.matchAll(/startup phase=(\w+) elapsed_s=([\d.]+)/g)].map(m => [m[1], Number(m[2])])) };
    samples.push(result);
    console.log(JSON.stringify(result));
  } finally {
    if (child.exitCode === null && child.signalCode === null && child.pid) {
      child.kill('SIGINT');
      const timer = setTimeout(() => child.kill('SIGKILL'), 40_000);
      const status = await ended;
      clearTimeout(timer);
      if (status.code !== 0) throw new Error(`server did not shut down cleanly: ${JSON.stringify(status)}\n${logs}`);
    }
  }
}
const quantile = (field, q) => samples.map(s => s[field]).sort((a, b) => a - b)[Math.ceil(samples.length * q) - 1];
console.log(JSON.stringify({ summary: true, runs, cache_condition: cache, polling_interval_s: 0.010,
  ready_p50_s: quantile('ready_s', 0.5), ready_p95_s: quantile('ready_s', 0.95), ready_max_s: quantile('ready_s', 1),
  useful_p50_s: quantile('useful_s', 0.5), useful_p95_s: quantile('useful_s', 0.95), useful_max_s: quantile('useful_s', 1) }));
