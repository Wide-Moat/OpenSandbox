# What this fork changes

This repository tracks [`opensandbox-group/OpenSandbox`](https://github.com/opensandbox-group/OpenSandbox).
The upstream `LICENSE` (Apache-2.0) applies unchanged, and so do the project's name and
branding. Every change here is an ordinary source commit, one per change, so `git rebase`
onto a later upstream commit shows exactly which of them upstream has since absorbed.

**Base:** `09e3584c5f71dd4887555d7ba3db6a24ddd9c404` (2026-09-11), marked by the
`upstream-base` tag.

**Branches.** `main` is a pristine mirror of upstream's `main` and is never committed to;
it exists so that a pull request against upstream is one click away. `wm` is this branch:
`upstream-base` plus the changes below, always rebased, never merged. A branch named
`up/<id>-…` is one change cherry-picked onto upstream's `main` for sending upstream.

## Why

We run sandboxes under **gVisor** with **no privileged containers, no added capabilities
and no hostPath**, and enforce egress with a **CNI-level policy outside the pod**.

Upstream's own [network isolation guide](docs/architecture/network-isolation.md#runtime-compatibility)
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
| **WM-1** | The egress sidecar can be told that enforcement lives outside the pod: it then installs no DNS or HTTP redirect, sets no `SO_MARK`, runs mitmproxy as a regular forward proxy, and the credential vault stops requiring nftables | `components/egress/{main.go,shutdown.go,mitmproxy_transparent.go}`, `pkg/{constants,dnsproxy,credentialvault,mitmproxy}` | `OPENSANDBOX_EGRESS_ENFORCEMENT`, default `sidecar` | `TestWM1*` in four packages | not yet sent |
| **WM-2** | The server configures that: no `NET_ADMIN` on the sidecar, the variable injected server-side, the two validators that reject gVisor and non-`dns+nft` modes stop applying, and the startup warning that predicts those rejections stops being printed when they will not happen | `server/…/config.py`, `services/{constants,validators,runtime_resolver}.py`, `services/k8s/{egress_helper,create_helpers,workload_provider,batchsandbox_provider,agent_sandbox_provider,kubernetes_service}.py`, `services/docker/networking.py` | `[egress] enforcement`, default `"sidecar"` | `test_wm2_*` in `test_config.py`, `test_validators.py`, `test_runtime_resolver.py`, `k8s/test_egress_helper.py` | not yet sent |
| **WM-4** | `[tenants] auth_token` can come from the environment, so the config file need not be a secret | `server/…/config.py` | `OPENSANDBOX_TENANTS_AUTH_TOKEN`, unset by default | `test_wm4_*` in `test_config.py` | not yet sent |
| **WM-6** | The controller's cache can be scoped to named namespaces, so two installations can share a cluster | `kubernetes/cmd/controller/main.go`, `charts/opensandbox-controller` | `--watch-namespaces`, empty (cluster-wide) by default | `TestWM6*` in `cmd/controller` | not yet sent |
| **WM-7** | The stop hook waits for mitmdump only when one was actually signalled — 51 ms against 1066 ms on every sandbox stop | `components/egress/scripts/cleanup.sh` | none; a plain fix | `TestWM7*` in `components/egress` | not yet sent |
| **WM-8** | The credential vault can be filled before the sandbox starts, so a sandbox that needs a credential ON ITS BOOT PATH gets one: the API cannot serve that case, because a client can only write the vault after the create call returns, the server does not answer that call until the pod is Ready, and the pod is not Ready until its own startup has finished | `components/egress/{policy_server.go,pkg/constants}`, `server/…/api/schema.py`, `services/{constants,docker/docker_service,k8s/{egress_helper,create_helpers,workload_provider}}.py` | `credentialProxy.seed` in the create request, which the server renders into `OPENSANDBOX_EGRESS_CREDENTIAL_VAULT_SEED` on the sidecar; `…_SEED_FILE` is a separate sidecar-only variable for a file already placed there, and takes precedence. All three unset by default | `TestWM8*` in `components/egress`, `test_wm8_*` in `k8s/test_egress_helper.py` | not yet sent |
| **WM-9** | A pause with no snapshot registry records failure before stopping running tasks | `kubernetes/cmd/controller/main.go`, `internal/controller/batchsandbox_{controller,pause_resume}.go` | existing `--snapshot-registry`, empty by default; early refusal of an operation that cannot succeed | `TestWM9PausePreflight_MissingRegistryPreservesRunningTask` | not yet sent |

Every test here was **run against the unmodified tree first** and fails there on
behaviour: the dialer still installs a `Control` hook, `Ready` still answers "requires
dns+nft egress enforcement", the manifest still carries `NET_ADMIN`, `[egress]
enforcement` is "accepted but not applied", the startup warning still predicts a
rejection that external enforcement does not perform, the TOML value still beats the
environment, the controller offers no `-watch-namespaces` among its flags, and the hook
still waits 1.046 s. Where naming a new symbol would have turned that into a compile
error — which proves only that a symbol is missing, and goes green the moment one exists
with nothing behind it — the test reaches the behaviour by another route: a literal
variable name, `inspect.signature`, `dataclasses.fields`, or reflection.

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

## Upstream's own workflows are disabled here

A fork inherits 25 workflows, and several of them publish: to PyPI, to Docker Hub, to
GitHub Pages, plus a multi-hour end-to-end suite. GitHub Actions is therefore **disabled
for this repository entirely** until the ones we want are enabled deliberately.

The lesson behind that caution is recorded rather than re-learned: on another fork here,
upstream's `Release` workflow ran on the first push, cut a release, and **moved the base
tag onto a fork commit** — after which every gate comparing against that tag was
comparing against the wrong tree and reporting success.

## Keeping the set honest

`hack/wm-check.sh` requires three independently derived sets to agree: the ids in the
commit messages on this branch, the ids in the table above, and the ids naming tests in
the tree. It also refuses to report success having found none, because three empty sets
agree with each other.

It reads the ids with `grep` rather than `git log --format='%(trailers)'`: git parses only
the last block of a message as trailers, these commits end with a sign-off block, and the
parser reports nothing at all. Measured, not assumed.
