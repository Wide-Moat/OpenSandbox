// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 OpenSandbox Contributors
import http from 'k6/http';
import execution from 'k6/execution';
import { sleep } from 'k6';

const target = __ENV.OSB_TARGET;
const key = __ENV.OSB_KEY;
const image = __ENV.OSB_IMAGE;
const runId = __ENV.OSB_RUN_ID;
const pool = __ENV.OSB_POOL || '';
const iterations = Number(__ENV.OSB_ITERATIONS || '1');
const idPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
if (!/^https:\/\/[A-Za-z0-9.-]+(?::[0-9]+)?$/.test(target || '') || target !== __ENV.OSB_APPROVED_TARGET ||
    !key || /[\r\n]/.test(key) || !/@sha256:[a-f0-9]{64}$/.test(image || '') ||
    !idPattern.test(runId || '') || !Number.isInteger(iterations) || iterations < 1 || iterations > 100 ||
    !__ENV.OSB_PROFILE) throw new Error('Explicit approved target, credential, digest, run ID, profile and bounded iterations required');
const profile = JSON.parse(open(__ENV.OSB_PROFILE));
if (profile.target !== target || profile.image !== image || profile.concurrency !== 1 || profile.runtime !== 'runsc' ||
    !['warm', 'cached-cold'].includes(profile.mode) ||
    (profile.mode === 'warm' ? !/^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(pool) || pool.length > 253 : pool !== ''))
  throw new Error('Profile must match target, image, runtime, serial mode and pool selection');
for (const field of ['namespace', 'nodeProfile', 'serverDigest', 'controllerDigest'])
  if (typeof profile[field] !== 'string' || !profile[field]) throw new Error('Profile provenance missing');
for (const field of ['serverDigest', 'controllerDigest'])
  if (!/^sha256:[a-f0-9]{64}$/.test(profile[field])) throw new Error('Immutable component digests required');

export const options = {
  scenarios: { sample: { executor: 'shared-iterations', vus: 1, iterations, maxDuration: '10m', gracefulStop: '120s' } },
  maxRedirects: 0, insecureSkipTLSVerify: false, summaryTrendStats: ['min', 'med', 'p(95)', 'p(99)', 'max'],
};
function assertExecution() {
  const o = execution.test.options;
  const scenarios = o.scenarios;
  if (o.httpDebug || o.insecureSkipTLSVerify || o.maxRedirects !== 0 || Object.keys(scenarios).length !== 1 ||
      scenarios.sample?.vus !== 1 || scenarios.sample?.iterations !== iterations ||
      scenarios.sample?.executor !== 'shared-iterations' ||
      !['10m', '10m0s', '600s'].includes(scenarios.sample?.maxDuration) ||
      !['2m', '2m0s', '120s'].includes(scenarios.sample?.gracefulStop))
    execution.test.abort('Unsafe execution override refused');
}
export function setup() { assertExecution(); }
const clock = () => execution.instance.currentTestRunDuration;
function request(method, path, body, timeout = '5s') {
  return http.request(method, target + path, body === undefined ? null : JSON.stringify(body), {
    headers: { 'OPEN-SANDBOX-API-KEY': key, 'Content-Type': 'application/json' }, timeout, redirects: 0,
    tags: { name: 'sandbox-performance-' + method },
  });
}
function json(response, status) {
  if (response.status !== status || response.error_code) throw new Error('http');
  return response.json();
}
function list(marker) {
  const d = json(request('GET', '/v1/sandboxes?metadata=' + encodeURIComponent('acceptance=' + marker)), 200);
  if (!Array.isArray(d.items) || d.pagination?.hasNextPage !== false ||
      d.pagination.totalItems !== d.items.length || d.items.length > 1 ||
      d.items.some(s => !idPattern.test(s.id || '') || s.metadata?.acceptance !== marker)) throw new Error('list');
  return d.items;
}
function clean(marker, id) {
  // A timeout may conceal a successful create. Never equate unknown ID with absence.
  const ids = new Set(id ? [id] : []);
  for (const s of list(marker)) ids.add(s.id);
  for (const value of ids) {
    const d = request('DELETE', '/v1/sandboxes/' + value);
    if (![200, 202, 204, 404].includes(d.status)) return false;
  }
  const deadline = clock() + 10000;
  while (clock() < deadline) {
    if (list(marker).length === 0) {
      for (const value of ids) if (request('GET', '/v1/sandboxes/' + value).status !== 404) return false;
      return true;
    }
    sleep(.2);
  }
  return false;
}
export default function () {
  assertExecution(); // Also enforce limits if --no-setup was supplied.
  const iteration = execution.scenario.iterationInTest;
  const marker = runId + '-' + iteration;
  const sample = { runId, iteration, profile, requestedPool: pool, sandboxId: '',
    startedAt: Date.now(), finishedAt: 0, elapsedMs: 0, ok: false, cleanup: false };
  const start = clock();
  let phase = 'create';
  try {
    const body = { image: { uri: image }, entrypoint: ['sleep', '300'], timeout: 300,
      resourceLimits: { cpu: '250m', memory: '512Mi' }, metadata: { acceptance: marker } };
    if (pool) body.extensions = { poolRef: pool };
    const created = json(request('POST', '/v1/sandboxes', body, '30s'), 202);
    if (!idPattern.test(created.id || '')) throw new Error('id');
    sample.sandboxId = created.id;
    phase = 'exec';
    const base = '/v1/sandboxes/' + created.id + '/proxy/44772';
    const response = request('POST', base + '/command', { command: 'echo ' + marker, cwd: '/', background: true });
    if (response.status !== 200 || response.error_code) throw new Error('exec');
    let command;
    for (const line of response.body.split('\n')) {
      if (line.startsWith('data:')) {
        const event = JSON.parse(line.slice(5));
        if (event.type === 'init') { command = event.text; break; }
      }
    }
    if (!idPattern.test(command || '')) throw new Error('command');
    const deadline = clock() + 10000;
    let complete = false;
    while (clock() < deadline) {
      const state = json(request('GET', base + '/command/status/' + command), 200);
      if (state.id !== command || typeof state.running !== 'boolean' || state.error) throw new Error('status');
      if (!state.running) { complete = state.exit_code === 0; break; }
      sleep(.2);
    }
    if (!complete) throw new Error('incomplete');
    const logs = request('GET', base + '/command/' + command + '/logs?cursor=0');
    if (logs.status !== 200 || !logs.body.split('\n').some(line => line === marker)) throw new Error('marker');
    sample.ok = true;
  } catch {
    sample.failedPhase = phase; // Never log response bodies, headers or credentials.
  } finally {
    sample.finishedAt = Date.now();
    sample.elapsedMs = clock() - start;
    try { sample.cleanup = clean(marker, sample.sandboxId); } catch { sample.cleanup = false; }
    console.log(JSON.stringify(sample));
  }
  if (!sample.ok || !sample.cleanup) execution.test.abort('Failed sample or unconfirmed cleanup; inspect retained evidence');
}
