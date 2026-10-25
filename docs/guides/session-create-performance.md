---
title: Session creation performance evidence
description: Collect bounded real-API timings and independently classify each sample.
---

# Session creation performance evidence

`test/perf/session-create.js` is an opt-in, single-client k6 instrument. It creates
one sandbox at a time, runs a unique command marker, validates exit status and output,
and deletes the sandbox. The measured boundary starts before POST create and ends
at validated command output. It includes client work, polling and transport. It is
not isolated runtime startup or exec orchestration overhead.

No target, credential or image is supplied by default. Obtain installation-specific
load authorization before running; the script does not create capacity, clear caches,
or enable a pool. A configured limit is not permission to use that limit. Default
iterations is one (diagnostic only), maximum 100, with a ten-minute scenario limit and
120-second completion allowance. The script stops after a failed attempt or cleanup.

## Collect

Set `OSB_TARGET` to an HTTPS origin and `OSB_APPROVED_TARGET` to the independently
approved exact same origin. Supply `OSB_KEY` securely through the process environment,
not command arguments. Do not enable HTTP debug logging or insecure TLS. Set
`OSB_IMAGE` to a digest-pinned image that supports `sleep` and shell `echo`,
`OSB_RUN_ID` to a fresh identifier, and `OSB_PROFILE` to a JSON file with these fields:

- `namespace`, `runtime` (`runsc`), and `nodeProfile` (reference to recorded CPU/RAM,
  quotas and load-generator location);
- `serverDigest`, `controllerDigest` (`sha256:` followed by 64 hexadecimal characters);
- `image` (same as `OSB_IMAGE`), `target` (same as `OSB_TARGET`), `concurrency` (1);
- `mode`: `cached-cold` or `warm`. Warm mode additionally requires `OSB_POOL`.

```sh
# All OSB_* inputs must already be provided through the authorized environment.
k6 run --log-format raw --console-output samples.jsonl test/perf/session-create.js
node test/perf/evaluate.mjs samples.jsonl observations.json
```

Use a new output file per run. `OSB_ITERATIONS` is optional (1..100). Retain the k6
exit status and summary together with samples. An interruption can omit a final row;
comparison with the predeclared count must not discard that attempt. Unknown-ID
create failures use the run/iteration metadata filter for cleanup; inability to establish
absence is a failure. TTL is a backstop, not proof of cleanup. Independently verify
pod/PVC absence before accepting the observer's `deleted` field.

## Independent observations

The evaluator accepts an envelope with `runId`, predeclared `expected`, `profile` and
`observations`. Each observer row names `runId`, `iteration`, `sandboxId`, `namespace`,
`image`, `runtime`, `podUID`, `nodeUID`, `nodeProfile`, `serverDigest`,
`controllerDigest`, `observedAt` (UTC epoch milliseconds), `deleted: true`
and `sourceArtifact`. Preserve the actual cluster snapshot at that source path.
The evaluator checks correlation, not the authenticity of manually supplied evidence.

For cached cold samples, supply `cachedBeforeCreate: true` and `cacheObservedAt`
before the attempt's `startedAt`, plus `cacheNodeUID` matching the actual assigned
`nodeUID`. Verify the image on that node.
For warm samples, supply `pool`, `preClaimAt` before `startedAt`, and
`readyPodUIDs` from the pre-claim snapshot. The assigned `podUID` must be in that
set. An allocation response or requested `poolRef` alone does not establish a hit.
Use synchronized observer clocks and retain the synchronization evidence. Reused
pod UIDs across the cohort are not accepted.

## Verdicts and limits

At least 100 complete, independently classified samples are needed for PASS. The
nearest-rank p99 limit is 2000 ms for cached cold and 500 ms for warm. Errors and
cleanup failures fail the entire run, even a short one. Missing attempts,
classification or provenance yield INCONCLUSIVE. Malformed/duplicate input yields
INVALID. Exit codes: PASS 0, FAIL 1, INCONCLUSIVE 2, INVALID 3. Raw samples and
p50/p95/p99/max remain necessary evidence; a green k6 process alone is not acceptance.

This instrument does not implement cold image pull, substrate startup, pool
exhaustion/replenishment, recycle isolation, burst/soak, exec-only overhead, egress,
noisy-neighbor or kill-switch tests. Equivalent-profile baseline regression remains
open; these tests must not be inferred from this creation cohort. No performance
claim is made by offline evaluator tests or `k6 inspect`.
