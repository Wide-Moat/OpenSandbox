// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 OpenSandbox Contributors
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const finite = n => typeof n === 'number' && Number.isFinite(n) && n >= 0;
const nonempty = s => typeof s === 'string' && s.length > 0;
const digest = s => typeof s === 'string' && /^sha256:[a-f0-9]{64}$/.test(s);
const profileKeys = ['namespace', 'image', 'serverDigest', 'controllerDigest', 'runtime', 'nodeProfile', 'target', 'concurrency', 'mode'];
const sameProfile = (a, b) => a && b && profileKeys.every(k => a[k] === b[k]);

// Observations must be produced independently from cluster evidence, never inferred
// from poolRef or an API allocation response. This checks correlation, not authenticity.
export function evaluate(input) {
  const result = (verdict, reason, extra = {}) => ({ verdict, reason, ...extra });
  if (!input || !Array.isArray(input.samples) || !Array.isArray(input.observations))
    return result('INVALID', 'samples and observations arrays required');
  const { samples, observations, profile: p, expected, runId } = input;
  if (!nonempty(runId) || !Number.isInteger(expected) || expected < 1 || expected > 100 ||
      !p || !profileKeys.every(k => p[k] !== undefined) || p.concurrency !== 1 ||
      !['cached-cold', 'warm'].includes(p.mode) || p.runtime !== 'runsc' ||
      !digest(p.serverDigest) || !digest(p.controllerDigest) ||
      typeof p.image !== 'string' || !/@sha256:[a-f0-9]{64}$/.test(p.image) ||
      !['namespace', 'nodeProfile', 'target'].every(k => nonempty(p[k])))
    return result('INVALID', 'complete bounded profile and immutable images required');
  const seen = new Set();
  for (const s of samples) {
    if (!s || s.runId !== runId || !Number.isInteger(s.iteration) || s.iteration < 0 ||
        s.iteration >= expected || seen.has(s.iteration) || !sameProfile(p, s.profile) ||
        typeof s.ok !== 'boolean' || typeof s.cleanup !== 'boolean' ||
        !finite(s.elapsedMs) || !finite(s.startedAt) || !finite(s.finishedAt) || s.finishedAt < s.startedAt)
      return result('INVALID', 'invalid, duplicate or mismatched attempt');
    seen.add(s.iteration);
  }
  const observed = new Map();
  for (const o of observations) {
    if (!o || !Number.isInteger(o.iteration)) return result('INVALID', 'invalid observer row');
    // Other runs must not replace an observation for this run.
    const key = `${o.runId}:${o.iteration}`;
    if (observed.has(key)) return result('INVALID', 'duplicate observer row');
    observed.set(key, o);
  }
  const failed = samples.filter(s => !s.ok || !s.cleanup).length;
  if (failed) return result('FAIL', 'attempt or API cleanup failed', { attempted: samples.length, failed });
  if (samples.length !== expected) return result('INCONCLUSIVE', 'planned attempts missing');
  if (samples.length < 100) return result('INCONCLUSIVE', 'at least 100 attempts required');
  const pods = new Set();
  for (const s of samples) {
    const o = observed.get(`${runId}:${s.iteration}`);
    if (!o || !nonempty(s.sandboxId) || o.sandboxId !== s.sandboxId ||
        o.namespace !== p.namespace || o.image !== p.image || o.runtime !== p.runtime ||
        o.serverDigest !== p.serverDigest || o.controllerDigest !== p.controllerDigest ||
        o.nodeProfile !== p.nodeProfile || !nonempty(o.nodeUID) ||
        !nonempty(o.podUID) || pods.has(o.podUID) || !nonempty(o.sourceArtifact) ||
        !finite(o.observedAt) || o.observedAt < s.startedAt || o.deleted !== true)
      return result('INCONCLUSIVE', 'independent identity, runtime, image and deletion evidence required');
    pods.add(o.podUID);
    if (p.mode === 'warm') {
      if (!nonempty(s.requestedPool) || o.pool !== s.requestedPool || !finite(o.preClaimAt) ||
          o.preClaimAt >= s.startedAt || !Array.isArray(o.readyPodUIDs) || !o.readyPodUIDs.includes(o.podUID))
        return result('INCONCLUSIVE', 'warm pod was not independently correlated before claim');
    } else if (s.requestedPool !== '' || o.cachedBeforeCreate !== true || o.cacheNodeUID !== o.nodeUID ||
               !finite(o.cacheObservedAt) || o.cacheObservedAt >= s.startedAt) {
      return result('INCONCLUSIVE', 'cached cold classification missing');
    }
  }
  const times = samples.map(s => s.elapsedMs).sort((a, b) => a - b);
  const percentile = n => times[Math.ceil(n * times.length) - 1];
  const limitMs = p.mode === 'warm' ? 500 : 2000;
  const stats = { attempted: samples.length, failed: 0, p50: percentile(.5), p95: percentile(.95),
    p99: percentile(.99), max: times.at(-1), limitMs, method: 'nearest-rank' };
  return result(stats.p99 <= limitMs ? 'PASS' : 'FAIL', 'classified create-to-exec-marker cohort', stats);
}

// Read raw JSON lines written with k6 --log-format raw --console-output samples.jsonl.
// Observation envelope contains runId, expected, profile and independent observations.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 4) throw new Error('usage: node evaluate.mjs samples.jsonl observations.json');
    const samples = readFileSync(process.argv[2], 'utf8').split('\n').filter(s => s.trim()).map(s => JSON.parse(s));
    const input = { ...JSON.parse(readFileSync(process.argv[3], 'utf8')), samples };
    const verdict = evaluate(input);
    console.log(JSON.stringify(verdict, null, 2));
    process.exitCode = { PASS: 0, FAIL: 1, INCONCLUSIVE: 2, INVALID: 3 }[verdict.verdict];
  } catch {
    console.error('INVALID: unreadable or malformed evidence; expected JSON lines and observation envelope');
    process.exitCode = 3;
  }
}
