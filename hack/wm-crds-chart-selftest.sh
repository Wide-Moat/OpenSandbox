#!/usr/bin/env bash
# The CRD chart publisher and its visibility check, against inputs whose verdict is known in
# advance. Run before either is believed -- in CI, in the job that publishes.
#
# Hermetic: no network. The --push and --probe cases run against a stand-in registry
# (hack/testdata/wm-crds-chart/registry-stub) in front of the real helm, which can refuse a
# lookup, fail an upload, or already hold a version -- the cases that decide whether a published
# version is ever written over. The packaging cases use the real CRDs in
# kubernetes/config/crd/bases, because those are what is published.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
sut="$here/wm-crds-chart.sh"
vis="$here/wm-package-visibility.sh"
fx="$here/testdata/wm-crds-chart"
fail=0
expect() {  # expect <label> <exit> <text> <command...>
  local label=$1 want=$2 text=$3; shift 3
  local out rc=0
  out=$("$@" 2>&1) || rc=$?
  if [ "$rc" = "$want" ] && printf '%s' "$out" | grep -qF -- "$text"; then echo "ok   $label"
  else echo "FAIL $label: exit $rc, wanted $want with '$text'"; printf '%s\n' "$out" | tail -5; fail=1; fi
}
check() {  # check <label> <command...>: a fact about what a case left behind
  local label=$1; shift
  if "$@"; then echo "ok   $label"; else echo "FAIL $label"; fail=1; fi
}
sha256() { { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | awk '{ print $1 }'; }
work=$(mktemp -d) || { echo "FAIL cannot create a temporary working directory"; exit 1; }
out="$work/published.txt"
repo=oci://registry.example.invalid/wide-moat/charts
real_helm=$(command -v helm || true)
[ -n "$real_helm" ] || { echo "FAIL helm is not on PATH -- nothing here can run"; exit 1; }
# The number of CRDs is read from the source, not written here: a constant would keep passing
# after controller-gen added a fourth kind that the chart left out.
n_crds=$(cat "$root"/kubernetes/config/crd/bases/*.yaml | grep -c '^kind: CustomResourceDefinition$')
base=$(awk '$1 == "version:" { print $2; exit }' "$root/manifests/charts/controller/Chart.yaml")

# -- packaging, no registry --------------------------------------------------------------------
expect "the CRDs are packaged at <controller chart version>-g<sha7>" 0 "opensandbox-crds $base-gabc1234: $n_crds CRDs, packaged" \
  bash "$sut" abc1234 "$repo" "$out"
check "the out-file holds 'opensandbox-crds $base-gabc1234 -'" grep -qx "opensandbox-crds $base-gabc1234 -" "$out"
check "the chart is not committed anywhere: no crds/ directory in the tree outside the source" \
  [ -z "$(cd "$root" && git ls-files '*opensandbox-crds*' 'manifests/charts/*/crds/*')" ]
empty="$work/empty-crds"; mkdir "$empty"
expect "a CRD directory with nothing in it refuses, rather than publishing an empty chart" 2 "no CRD in" \
  env CRD_DIR="$empty" bash "$sut" abc1234 "$repo" "$out"
expect "a file the git source would apply and the chart would not is refused" 1 "notes.yml" \
  env CRD_DIR="$fx/stray" bash "$sut" abc1234 "$repo" "$out"
linked="$work/linked-crds"; mkdir "$linked"
cp "$root"/kubernetes/config/crd/bases/*.yaml "$linked/"
ln -s "$fx/stray/widgets.example.invalid.yaml" "$linked/widgets.example.invalid.yaml"
expect "a symlinked manifest beside the CRDs is refused, not silently left out" 1 "widgets.example.invalid.yaml is not a regular file" \
  env CRD_DIR="$linked" bash "$sut" abc1234 "$repo" "$out"
expect "a base version that is not major.minor.patch is refused" 1 "is not <major.minor.patch[-pre-release]>-g<sha7>" \
  env BASE_CHART="$fx/bad-version/Chart.yaml" bash "$sut" abc1234 "$repo" "$out"
# Upstream cuts release candidates; a pre-release base must still package, as one semver
# pre-release. Pinned here so it stays covered whatever the real chart's version is today.
expect "a pre-release base version is packaged at <base>-g<sha7>" 0 "opensandbox-crds 1.2.3-rc.1-gabc1234: $n_crds CRDs, packaged" \
  env BASE_CHART="$fx/rc-version/Chart.yaml" bash "$sut" abc1234 "$repo" "$out"
expect "a sha that is not seven hex characters is refused" 2 "is not seven hex characters" \
  bash "$sut" ABC "$repo" "$out"
expect "a repository without oci:// is refused" 2 "repository must be oci://" \
  bash "$sut" abc1234 registry.example.invalid/charts "$out"
expect "an unknown mode is refused, not read as a dry run" 2 "mode must be --push or --probe" \
  bash "$sut" abc1234 "$repo" "$out" --pusj
expect "no helm refuses" 2 "helm is not on PATH" \
  env PATH=/nonexistent "$(command -v bash)" "$sut" abc1234 "$repo" "$out"
helm_only="$work/helm-only"; mkdir "$helm_only"; ln -s "$real_helm" "$helm_only/helm"
for t in awk cat cmp dirname find grep head mkdir mktemp rm sed sort tail tar tr basename wc; do
  p=$(command -v "$t") && ln -s "$p" "$helm_only/$t"
done
expect "--push without crane refuses" 2 "crane is not on PATH" \
  env PATH="$helm_only" "$(command -v bash)" "$sut" abc1234 "$repo" "$out" --push

# -- against the stand-in registry --------------------------------------------------------------
registry() { local d="$work/registry-$1"; mkdir -p "$d"; : > "$d/push.log"; echo "$d"; }
# shellcheck disable=SC2329 # invoked through expect, as its command
stub() {  # stub <registry> [VAR=value...] <command...>
  local reg=$1; shift
  env PATH="$fx/registry-stub:$PATH" STUB_REAL_HELM="$real_helm" STUB_REGISTRY="$reg" "$@"
}
pkg=opensandbox-crds-$base-gabc1234.tgz

reg=$(registry fresh)
expect "a version the registry lacks is pushed, read back and its digest recorded" 0 "opensandbox-crds $base-gabc1234: pushed and read back" \
  stub "$reg" bash "$sut" abc1234 "$repo" "$out" --push
check "exactly one push reached the registry" [ "$(grep -c . "$reg/push.log")" = 1 ]
check "the out-file holds the digest the registry serves" \
  grep -qx "opensandbox-crds $base-gabc1234 sha256:$(sha256 "$reg/$pkg")" "$out"

# The same commit again -- a re-run. Read back and compared, never pushed over.
: > "$reg/push.log"
expect "a version already published is not pushed over" 0 "already published, not pushing over it" \
  stub "$reg" bash "$sut" abc1234 "$repo" "$out" --push
check "no push reached the registry" [ ! -s "$reg/push.log" ]

# The registry holds a DIFFERENT package under this version: one CRD edited. Pushing over it would
# rewrite what an installation has pinned; the publisher must fail and leave it alone.
tampered=$(registry tampered)
mkdir -p "$work/t/opensandbox-crds/crds"
cp "$root"/kubernetes/config/crd/bases/*.yaml "$work/t/opensandbox-crds/crds/"
printf 'apiVersion: v2\nname: opensandbox-crds\nversion: %s-gabc1234\n' "$base" > "$work/t/opensandbox-crds/Chart.yaml"
f="$work/t/opensandbox-crds/crds/sandbox.opensandbox.io_pools.yaml"
awk '{ print } $0 == "  name: pools.sandbox.opensandbox.io" { print "  labels: {tampered: \"yes\"}" }' "$f" > "$f.new" && mv "$f.new" "$f"
grep -q 'tampered' "$f" || { echo "FAIL the tampered fixture was not tampered with"; exit 1; }
"$real_helm" package "$work/t/opensandbox-crds" -d "$tampered" >/dev/null
before=$(sha256 "$tampered/$pkg")
expect "a published version whose CRDs are not the source fails, and is not overwritten" 1 "differs from kubernetes/config/crd/bases" \
  stub "$tampered" bash "$sut" abc1234 "$repo" "$out" --push
check "no push reached the registry" [ ! -s "$tampered/push.log" ]
check "the published package is byte for byte what it was" [ "$(sha256 "$tampered/$pkg")" = "$before" ]

# The registry serves, under this tag, a package whose Chart.yaml carries another version.
mislabelled=$(registry mislabelled)
sed -i.bak "s/-gabc1234/-gdeadbee/" "$work/t/opensandbox-crds/Chart.yaml" && rm -f "$work/t/opensandbox-crds/Chart.yaml.bak"
cp "$root/kubernetes/config/crd/bases/sandbox.opensandbox.io_pools.yaml" "$work/t/opensandbox-crds/crds/"
"$real_helm" package "$work/t/opensandbox-crds" -d "$work" >/dev/null
mv "$work/opensandbox-crds-$base-gdeadbee.tgz" "$mislabelled/$pkg"
expect "a published package carrying another version fails" 1 "carries version $base-gdeadbee" \
  stub "$mislabelled" bash "$sut" abc1234 "$repo" "$out" --push

# helm renders every CRD and still exits non-zero: the count alone would call that a clean package.
expect "a render that fails is a failure, whatever it printed" 1 "helm template failed" \
  env PATH="$fx/registry-stub:$PATH" STUB_REAL_HELM="$real_helm" STUB_REGISTRY="$work" STUB_TEMPLATE_FAILS=1 bash "$sut" abc1234 "$repo" "$out"

# A lookup the registry refuses is "cannot tell", not "absent": pushing could write over a
# version that exists and is hidden behind a bad credential.
denied=$(registry denied)
expect "a registry that refuses the lookup is not pushed to" 1 "cannot tell whether" \
  stub "$denied" STUB_CRANE=denied bash "$sut" abc1234 "$repo" "$out" --push
check "no push reached the registry" [ ! -s "$denied/push.log" ]

broken=$(registry broken)
expect "a failed upload fails" 1 "push failed" \
  stub "$broken" STUB_PUSH_FAILS=1 bash "$sut" abc1234 "$repo" "$out" --push

# --probe: what a pull request runs. The same lookup, nothing written.
probe=$(registry probe)
expect "--probe reports a version it would push" 0 "opensandbox-crds $base-gabc1234: absent, would push" \
  stub "$probe" bash "$sut" abc1234 "$repo" "$out" --probe
check "--probe pushed nothing" [ ! -s "$probe/push.log" ]
check "--probe records no digest for an unpublished version" grep -qx "opensandbox-crds $base-gabc1234 -" "$out"
expect "--probe refuses a registry it cannot read" 1 "cannot tell whether" \
  stub "$probe" STUB_CRANE=denied bash "$sut" abc1234 "$repo" "$out" --probe

# -- package visibility, against a stand-in packages API ----------------------------------------
held=$(registry held); cp "$reg/$pkg" "$held/"
nothing=$(registry nothing)
# shellcheck disable=SC2329 # invoked through expect, as its command
api() {  # api <case> <registry> <args...>
  local c=$1 r=$2; shift 2
  env PATH="$fx/api-stub:$fx/registry-stub:$PATH" STUB_API="$fx/api-stub/$c" STUB_REGISTRY="$r" GH_TOKEN=stub bash "$vis" "$@"
}
expect "a package with the visibility asked for passes" 0 "charts/opensandbox-crds: public" \
  api answers-public "$held" Wide-Moat "$repo/opensandbox-crds" public
expect "a package with another visibility fails" 1 "charts/opensandbox-crds is private, expected public" \
  api answers-private "$held" Wide-Moat "$repo/opensandbox-crds" public
expect "an absent package fails after a push" 1 "does not exist, yet it was just pushed" \
  api answers-absent "$nothing" Wide-Moat "$repo/opensandbox-crds" public
expect "an absent package is allowed where nothing was pushed, when the registry agrees" 0 "not published yet" \
  api answers-absent "$nothing" Wide-Moat "$repo/opensandbox-crds" public --allow-absent
expect "a package the registry holds but the API hides is a refusal" 2 "hidden from this token" \
  api answers-absent "$held" Wide-Moat "$repo/opensandbox-crds" public --allow-absent
STUB_CRANE=denied expect "a registry that cannot be asked about a 404 is a refusal" 2 "cannot tell whether" \
  api answers-absent "$nothing" Wide-Moat "$repo/opensandbox-crds" public --allow-absent
expect "a token that cannot read package metadata refuses" 2 "HTTP 403" \
  api answers-denied "$held" Wide-Moat "$repo/opensandbox-crds" public
expect "an unreadable API answer refuses rather than failing as 'not public'" 2 "cannot parse" \
  api answers-malformed "$held" Wide-Moat "$repo/opensandbox-crds" public
expect "an unknown visibility to expect is refused" 2 "expected visibility must be" \
  api answers-public "$held" Wide-Moat "$repo/opensandbox-crds" pubic
expect "no token refuses" 2 "GH_TOKEN is empty" \
  env GH_TOKEN= bash "$vis" Wide-Moat "$repo/opensandbox-crds" public

rm -rf "$work" || true
exit "$fail"
