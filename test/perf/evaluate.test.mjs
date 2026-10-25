// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 OpenSandbox Contributors
import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluate } from './evaluate.mjs';

const digest = 'sha256:' + 'a'.repeat(64);
function cohort(mode = 'cached-cold') {
  const profile = { namespace: 'test-stage', image: 'example/image@' + digest,
    serverDigest: digest, controllerDigest: digest, runtime: 'runsc', nodeProfile: 'node-profile-sha256',
    target: 'https://stage.example.test', concurrency: 1, mode };
  const samples = Array.from({ length: 100 }, (_, i) => ({ runId: 'run-1', iteration: i,
    sandboxId: 'sb-' + i, startedAt: 1000 + i * 1000, finishedAt: 1500 + i * 1000,
    elapsedMs: 400, ok: true, cleanup: true, requestedPool: mode === 'warm' ? 'test-pool' : '', profile }));
  const observations = samples.map(s => ({ runId: s.runId, iteration: s.iteration,
    sandboxId: s.sandboxId, namespace: profile.namespace, image: profile.image, podUID: 'pod-' + s.iteration,
    observedAt: s.finishedAt, deleted: true, runtime: 'runsc',
    cachedBeforeCreate: true, cacheObservedAt: s.startedAt - 1,
    pool: 'test-pool', preClaimAt: s.startedAt - 1, readyPodUIDs: ['pod-' + s.iteration],
    nodeUID: 'node-1', cacheNodeUID: 'node-1', nodeProfile: profile.nodeProfile,
    serverDigest: profile.serverDigest, controllerDigest: profile.controllerDigest, sourceArtifact: 'observer.json' }));
  return { runId: 'run-1', expected: 100, profile, samples, observations };
}
test('complete classified cohorts meet their fixed targets', () => {
  for (const mode of ['warm', 'cached-cold']) assert.equal(evaluate(cohort(mode)).verdict, 'PASS');
});
test('too few samples cannot certify p99', () => {
  const c = cohort(); c.expected = 3; c.samples = c.samples.slice(0, 3);
  assert.equal(evaluate(c).verdict, 'INCONCLUSIVE');
});
test('missing planned attempt is not silently discarded', () => {
  const c = cohort(); c.samples.pop(); assert.notEqual(evaluate(c).verdict, 'PASS');
});
test('failures and cleanup failures fail even a short run', () => {
  for (const field of ['ok', 'cleanup']) {
    const c = cohort(); c.samples[0][field] = false;
    assert.equal(evaluate(c).verdict, 'FAIL');
  }
});
test('invalid and duplicate timings cannot pass', () => {
  for (const value of [NaN, Infinity, -1, null, '400']) {
    const c = cohort(); c.samples[0].elapsedMs = value;
    assert.equal(evaluate(c).verdict, 'INVALID');
  }
  const c = cohort(); c.samples[1] = c.samples[0]; assert.equal(evaluate(c).verdict, 'INVALID');
});
test('requested pool alone is not warm evidence', () => {
  const c = cohort('warm'); c.observations[0].readyPodUIDs = ['other'];
  assert.equal(evaluate(c).verdict, 'INCONCLUSIVE');
});
test('cached image requires observation before creation', () => {
  const c = cohort(); c.observations[0].cacheObservedAt = c.samples[0].finishedAt;
  assert.equal(evaluate(c).verdict, 'INCONCLUSIVE');
});
test('identity, runtime and digest mismatch cannot pass', () => {
  for (const field of ['runId', 'sandboxId', 'namespace', 'image', 'runtime']) {
    const c = cohort(); c.observations[0][field] = 'wrong';
    assert.equal(evaluate(c).verdict, 'INCONCLUSIVE');
  }
});
test('missing provenance and duplicate observer rows cannot pass', () => {
  const c = cohort(); c.observations[0].sourceArtifact = '';
  assert.equal(evaluate(c).verdict, 'INCONCLUSIVE');
  const d = cohort(); d.observations.push(d.observations[0]);
  assert.equal(evaluate(d).verdict, 'INVALID');
});
test('warm target is stricter than cold target', () => {
  for (const mode of ['warm', 'cached-cold']) {
    const c = cohort(mode); c.samples.forEach(s => { s.elapsedMs = 600; });
    assert.equal(evaluate(c).verdict, mode === 'warm' ? 'FAIL' : 'PASS');
  }
});
test('mixed profiles and wrong planned sample count are invalid', () => {
  const c = cohort(); c.samples[0] = { ...c.samples[0], profile: { ...c.profile, runtime: 'runc' } };
  assert.equal(evaluate(c).verdict, 'INVALID');
  const d = cohort(); d.expected = 0; assert.equal(evaluate(d).verdict, 'INVALID');
});

test('cache and deployment provenance must match the actual node and release', () => {
  for (const field of ['cacheNodeUID', 'nodeProfile', 'serverDigest', 'controllerDigest']) {
    const c = cohort(); c.observations[0][field] = 'wrong';
    assert.equal(evaluate(c).verdict, 'INCONCLUSIVE');
  }
});
