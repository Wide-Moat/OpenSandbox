# What this fork changes

This repository tracks [`opensandbox-group/OpenSandbox`](https://github.com/opensandbox-group/OpenSandbox).
The upstream `LICENSE` (Apache-2.0) applies unchanged, and so do the project's name and
branding. Every change here is an ordinary source commit, one per change, so `git rebase`
onto a later upstream commit shows exactly which of them upstream has since absorbed, and
`up/<id>` is a single cherry-pick. `hack/wm-check.sh` enforces it: a commit that touches
anything outside `NOTICE-WIDE-MOAT.md`, `hack/` and `.github/` must name its change with
a `Wide-Moat-Change:` trailer, and no change may be named by two commits. A fix to a
change is folded into that change's commit, not committed beside it.

**Base:** `f3950db2499e8d572694bf9939e4bf985a2eab8a` (2026-09-25), marked by the
`upstream-base` tag.

**Branches.** `main` is a pristine mirror of upstream's `main` and is never committed to;
it exists so that a pull request against upstream is one click away. `wm` is this branch:
`upstream-base` plus the changes below, always rebased, never merged. A branch named
`up/<id>-…` is one change cherry-picked onto upstream's `main` for sending upstream.

## Why

We run sandboxes under **gVisor** with **no privileged containers, no added capabilities
and no hostPath**, and enforce egress with a **CNI-level policy outside the pod**.

Upstream's own [network isolation guide](docs/architecture/network/network-isolation.md#runtime-compatibility)
recommends that arrangement — "use a CNI-level FQDN policy (e.g., Cilium `toFQDNs`) for
network isolation alongside gVisor" — while the code returns `400` for exactly that
combination, and the egress sidecar cannot start there at all: gVisor implements neither
the iptables `nat` table nor `AF_NETLINK`/`NETFILTER`, and `CAP_NET_ADMIN` cannot be
granted to it.

Every change below is therefore shaped as **an option whose default is today's
behaviour**, so the same diff that this fork carries is the one offered upstream.

## Changes

| id | what | files | option, and its default | test | upstream |
|---|---|---|---|---|---|
| **WM-1** | The egress sidecar can be told that enforcement lives outside the pod: it then installs no DNS or HTTP redirect, sets no `SO_MARK`, runs mitmproxy as a regular forward proxy, and the credential vault stops requiring nftables. ⚠ Nothing in the pod then enforces a sandbox's `networkPolicy`: the DNS filter listens on 15353, which no resolver setting can name, so without the redirect it is out of the path, and the policy only decides which hosts vault bindings may name. The outside policy is the whole of the enforcement ([docs](docs/architecture/network/egress.md#enforcement-outside-the-pod)) | `components/egress/{main.go,shutdown.go,mitmproxy_transparent.go,netfilter.go}`, `pkg/{constants,dnsproxy,credentialvault,mitmproxy}`, `docs/architecture/network/{egress,network-isolation}.md` | `OPENSANDBOX_EGRESS_ENFORCEMENT`, default `sidecar` | `TestWM1*` in four packages and the component | not yet sent |
| **WM-2** | The server configures that: no `NET_ADMIN` on the sidecar, the variable injected server-side, the two validators that reject gVisor and non-`dns+nft` modes stop applying, and the startup warning that predicts those rejections stops being printed on Kubernetes, where they will not happen. A configuration pairing it with `mode = "dns+nft"` or an `[egress.upstream_proxy]` is refused at load, as the sidecar refuses it at startup, and so is one leaving `disable_ipv6` true, which Kubernetes carries out with a privileged init container. Docker never tells its sidecar, so there nothing changes | `server/…/config.py`, `services/{constants,helpers,validators,runtime_resolver}.py`, `services/k8s/{egress_helper,create_helpers,workload_provider,batchsandbox_provider,agent_sandbox_provider,kubernetes_service}.py`, `services/docker/networking.py` | `[egress] enforcement`, default `"sidecar"` (documented in `server/configuration.md`) | `test_wm2_*` in `test_config.py`, `test_validators.py`, `test_runtime_resolver.py`, `test_docker_service.py`, `k8s/test_egress_helper.py`, `k8s/test_create_path_egress.py` | not yet sent |
| **WM-4** | `[tenants] auth_token` can come from the environment, so the config file need not be a secret | `server/…/config.py`, `server/configuration.md`, `docs/guides/multi-tenancy.md` | `OPENSANDBOX_TENANTS_AUTH_TOKEN`, unset by default | `test_wm4_*` in `test_config.py` | not yet sent |
| **WM-6** | The controller's cache can be scoped to named namespaces, so two installations can share a cluster. The scope wraps the options handed to `ctrl.NewManager`, so there is no separate statement a rebase can drop or move past the call, and a test runs the built controller and sees it applied | `kubernetes/cmd/controller/main.go`, `manifests/charts/controller` (`values.yaml`, `README.md`) | `--watch-namespaces`, empty (cluster-wide) by default | `TestWM6*` in `cmd/controller` | not yet sent |
| **WM-7** | The stop hook waits for mitmdump only when one was actually signalled — 51 ms against 1066 ms on every sandbox stop | `components/egress/scripts/cleanup.sh` | none; a plain fix | `TestWM7*` in `components/egress` | not yet sent |
| **WM-8** | The credential vault can be filled before the sandbox starts, so a sandbox that needs a credential ON ITS BOOT PATH gets one: the API cannot serve that case, because a client can only write the vault after the create call returns, the server does not answer that call until the pod is Ready, and the pod is not Ready until its own startup has finished. Measured on a live installation: a WebDAV mount refused at 18:37:56, the pod Ready at 18:37:58, the vault written at 18:37:59. The seed travels in the sidecar's own environment and nowhere else: the one volume the sidecar shares with the sandbox is where the sandbox reads the proxy CA, so a seed there would be readable by the code the vault exists to keep the credential from. The sidecar loads it through the API's own decoder, preconditions and create, skipping only the wait for mitmdump, which starts after it | `components/egress/{policy_server.go,pkg/constants,pkg/credentialvault}`, `specs/sandbox-lifecycle.yml`, `server/…/api/schema.py`, `services/{constants,helpers,docker/{docker_service,networking},k8s/{egress_helper,create_helpers,workload_provider}}.py` | `credentialProxy.seed` in the create request (`CredentialVaultSeed` in `specs/sandbox-lifecycle.yml`: both lists, nothing else, and only with `enabled`, a `networkPolicy` and no `poolRef`, or the create is refused), which the server renders into `OPENSANDBOX_EGRESS_CREDENTIAL_VAULT_SEED` on the sidecar. Both unset by default | `TestWM8*` in `components/egress`, `test_wm8_*` in `test_credential_proxy_seed.py`, `k8s/test_egress_helper.py`, `k8s/test_create_path_egress.py`, `test_docker_service.py` | not yet sent |
| **WM-10** | A sandbox is not Ready until execd can answer: the main container asks execd's `/ping` (port 44772) with a startup probe every 1 s, so the pod turns Ready within a second of execd listening, and then with a readiness probe every 10 s, so a Ready pod whose execd dies is NotReady within about 30 s -- at a tenth of the `GET /ping` log lines a 1 s readiness probe cost (86,400 a day per sandbox). The probes reach the pod spec through the Kubernetes client's own serialiser, not the hand-written one, and the Windows profile, whose execd runs inside a guest that boots for minutes, keeps upstream's probe-less container. Without this the pod is Ready the moment its process starts, and the create call returns an id for a sandbox that refuses the next request. `/ping` rather than execd's `/ready`, which exists only from upstream `57ea7951` on: the server rolls out before execd, and against an older execd `/ready` is a 404 and no pod would ever be Ready. Move to `/ready` once execd is pinned at or after that commit | `server/…/services/{constants.py,k8s/provider_common.py,k8s/windows_profile.py}` | none; a plain fix | `test_wm10_*` in `k8s/test_sandbox_readiness_probe.py` | not yet sent |
| **WM-11** | The server's sandbox proxy refuses execd's `/internal/` routes, on the HTTP and the WebSocket route alike. Upstream's execd serves `POST /internal/init` without its access token — the call has to work before a token exists — and it applies a RuntimeBinding: the access-token hash, the environment, the lifecycle. The proxy route skips the server's own API-key check in single-tenant mode, so without this anyone who knows a sandbox id could rebind its execd. Refused for every spelling execd would route there: percent-encoded (execd routes on the decoded path), dot and empty segments, a decoded `?` or `#` that ends the path, and hops back through execd's own `/proxy/44772/`. And on every port, a path whose dot segments climb out of the port it names is refused: on Docker every port but 8080 resolves to execd itself as `<host>:<execd>/proxy/<port>`, and httpx resolves the dots before sending. Everything else — `/proxy/9223/…` to Chromium above all — is forwarded as before. The proxy is one way in; WM-12 closes the route where it is served | `server/…/{api/proxy.py,services/constants.py}` | none; a plain fix | `test_wm11_*` in `test_proxy_execd_internal.py` | not yet sent |
| **WM-12** | execd serves `POST /internal/init` only when it runs with `--runtime-init`, the mode in which a control plane is waiting to send it. Outside that mode upstream still answers it, unauthenticated, and it replaces the access-token hash and the environment — through the ingress gateway, which forwards any path to any port, from another pod, or from the sandbox itself, and even once execd has a token. Now it is a 404 there. This changes upstream's documented legacy behaviour, a late `/internal/init` becoming authoritative, which nothing in this repository sends; upstream's own runtime-init smoke is updated to match | `components/execd/pkg/{web/router.go,flag/flags.go}`, `components/execd/tests/runtime_init{.sh,_smoke.py}` | none; a plain fix | `TestWM12*` in `components/execd/pkg/web` | not yet sent |

Every test here was **run against the unmodified tree first** and fails there on
behaviour: the dialer still installs a `Control` hook, `Ready` still answers "requires
dns+nft egress enforcement", the manifest still carries `NET_ADMIN`, `[egress]
enforcement` is "accepted but not applied", the startup warning still predicts a
rejection that external enforcement does not perform, the TOML value still beats the
environment, the controller offers no `-watch-namespaces` among its flags, the hook
still sleeps a second after signalling nothing, the sandbox container carries no probe, the
proxy still forwards `/internal/init` to execd, and execd still answers it outside
runtime-init mode. Where naming
a new symbol would have turned that into a compile error — which proves only that a
symbol is missing, and goes green the moment one exists with nothing behind it — the
test reaches the behaviour by another route: a literal variable name,
`inspect.signature`, `dataclasses.fields`, or reflection.

## Deliberately not carried

- **Warm-pool changes.** We do not run a pool in this deployment. Upstream has since
  added `poolassign` with an image predicate, which covers most of what we would have
  needed; the remaining gap — an explicit `poolRef` silently ignoring the requested image
  — belongs upstream as an issue, not as a patch here.
- **Chart RBAC and namespace gates.** Those were artefacts of a different deployment tool.
  ArgoCD applies cluster RBAC, and the namespace is set with `namespaceOverride`, which is
  configuration rather than a change.
- **A corporate CA baked into the egress image.** `OPENSANDBOX_EGRESS_MITMPROXY_UPSTREAM_TRUST_DIR`
  already exists for that, so it is a mount, not a patch.
- **The "pool scale is not ready" reconcile error.** Fixed upstream in `0d82d87b`.

## Upstream's own workflows here

A fork inherits upstream's workflows, and several of them publish: to PyPI, to Docker
Hub, to GitHub Pages, plus a multi-hour end-to-end suite. Actions is enabled here so that
`wm-ci` can run. Upstream's workflows are disabled **one by one** through the API, with
`gh workflow disable`. Measured on 2026-09-25: 18 are `disabled_manually`. Eight are
active: `wm-ci`, plus seven of upstream's test workflows (`detect-changes`, `egress-test`,
`execd-test`, `ingress-test`, `kubernetes-test`, `nodeagent-test`, `server-test`). Those
seven trigger only on pull requests to `main` or through `workflow_call`, so nothing here
fires them by itself.

`wm-ci` **calls** upstream's test workflows for every area this fork changes —
`egress-test`, `execd-test`, `kubernetes-test`, `server-test` and `helm-docs` — and gates
the images on them, rather than keeping its own copy of their steps. A copy had already
lost the mitmscript tests, the nft regression, gofmt and golangci-lint, the coverage floor,
the Windows leg and the chart-docs drift check. Three edits to those five files make that
possible, and nothing else in them changes: a `workflow_call` trigger; a concurrency group
named after the workflow instead of `${{ github.workflow }}`, which in a called workflow
is the caller's name, so all five would share and cancel one group; and, in a fork, a
hosted runner where upstream names `self-hosted`, because a fork has none and a job
waiting for one never starts.

⚠ A disable applies to one workflow file, so **every rebase must disable the files it
brings in**. GitHub registers a new workflow file as enabled. Its first push to `wm`, the
default branch, is also what arms any `schedule:` in it. The move from `09e3584c` to
`f3950db` brought four: `fast-sandbox-test.yml`, `release-packages.yml`,
`verify-license.yml`, and `release-umbrella.yml`, which runs on a weekly schedule and
publishes. `git diff --diff-filter=A --name-only <old base> <new base> -- .github/workflows`
lists them.

The lesson behind that caution is recorded rather than re-learned: on another fork here,
upstream's `Release` workflow ran on the first push, cut a release, and **moved the base
tag onto a fork commit** — after which every gate comparing against that tag was
comparing against the wrong tree and reporting success.

## Keeping the set honest

`hack/wm-check.sh` requires three independently derived sets to agree: the ids in the
commit messages on this branch, the ids in the table above, and the ids naming tests in
the tree. It also refuses to report success having found none, because three empty sets
agree with each other, and refuses a commit that changes the product without naming its
change.

`hack/wm-fail-on-base.sh` runs every WM test against unmodified upstream and requires each
to fail there on behaviour — read from `go test -json` events and pytest's JUnit report,
every case of a parametrised test counted — or to be argued as a guard, an exemption or a
test that cannot build there. Every change must keep at least one test that fails there.
Both gates find the tests with the one definition in `hack/wm-tests.sh`.

`hack/wm-gates-selftest.sh` runs both gates' classifiers against inputs whose answer is
known -- a test id only in a comment, a product commit that names no change, a test binary
that cannot start, a missing fixture, a parametrised test half of whose cases pass, a
change whose only test is a guard -- and runs in CI before the gate that relies on them.

It reads the ids with `grep` rather than `git log --format='%(trailers)'`: git parses only
the last block of a message as trailers, these commits end with a sign-off block, and the
parser reports nothing at all. Measured, not assumed.
