#!/usr/bin/env bash
# Package this fork's CustomResourceDefinitions as the Helm chart `opensandbox-crds`, prove the
# package holds exactly the CRDs in the tree, and with --push publish it and read it back.
#
#   hack/wm-crds-chart.sh <sha7> <oci-repository> <out-file> [--probe | --push]
#
#   (none)    package and compare with the source. No registry is contacted.
#   --probe   also ask the registry whether the version exists, and write nothing to it -- what a
#             pull request runs, so the lookup --push depends on is exercised before wm needs it.
#   --push    publish the version if the registry lacks it, then read it back and compare it.
#
# out-file: one line, "opensandbox-crds <version> <digest>" -- "-" when no digest was read.
# exit 0 published or checked; 1 the package differs from the source, or a lookup, push or
# read-back failed; 2 could not run.
#
# WHY A CHART. An installation of the Wide Moat platform used to apply these CRDs straight from
# this repository, at the branch `wm`: a source that moves under every installation, and one a
# buyer installing from a release would have to reach GitHub to read. A chart version is
# immutable and travels with the release like any other chart.
#
# WHAT IS PACKAGED. kubernetes/config/crd/bases/*.yaml -- controller-gen's output, the files that
# Application applied from git -- copied into the chart's crds/ AT BUILD TIME. Nothing of the chart
# is committed: a second committed copy of a CRD is a copy that drifts from its generator, which is
# why the platform never used the copies in manifests/charts. The directory must hold nothing else,
# because the git source applied every manifest in it and the chart must not apply less.
#
# THE VERSION is <manifests/charts/controller/Chart.yaml version>-g<sha7>: the controller release
# these definitions belong to, and the commit they were built from. It is a semver PRE-RELEASE, so
# helm resolves no range to it; a consumer pins it exactly, and there is no "latest" to drift onto.
#
# A PUBLISHED VERSION IS NEVER WRITTEN OVER. The push happens only when the registry says the
# version is ABSENT, in the words a registry uses for that (MANIFEST_UNKNOWN / NAME_UNKNOWN).
# Any other failure to look -- denied, unauthorised, unreachable -- is "cannot tell", and that is
# a failure, not a licence to push. A version already there is read back and compared with the
# source like a fresh one; if it differs, the run fails and the package stays as it is.
# hack/wm-crds-chart-selftest.sh drives each of these against a stand-in registry.
#
# Overridable for the self-test: CRD_DIR (the CRDs), BASE_CHART (the Chart.yaml giving the base).
set -uo pipefail
refuse() { echo "REFUSING TO REPORT: $*" >&2; exit 2; }
sha7=${1:-}; repo=${2:-}; out=${3:-}; mode=${4:-}
[[ "$sha7" =~ ^[0-9a-f]{7}$ ]] || refuse "'$sha7' is not seven hex characters"
case "$repo" in oci://?*) ;; *) refuse "repository must be oci://<host>/<path>, got '$repo'" ;; esac
[ -n "$out" ] || refuse "no out-file"
case "$mode" in ''|--push|--probe) ;; *) refuse "mode must be --push or --probe (or nothing), got '$mode'" ;; esac
command -v helm >/dev/null 2>&1 || refuse "helm is not on PATH"
if [ -n "$mode" ]; then
  command -v crane >/dev/null 2>&1 || refuse "crane is not on PATH -- whether a version exists cannot be asked"
fi
root=$(cd "$(dirname "$0")/.." && pwd)
crds=${CRD_DIR:-$root/kubernetes/config/crd/bases}
base_chart=${BASE_CHART:-$root/manifests/charts/controller/Chart.yaml}
name=opensandbox-crds
[ -d "$crds" ] || refuse "no CRD directory at $crds"
[ -f "$base_chart" ] || refuse "no $base_chart to take the version from"
: > "$out" || refuse "cannot write $out"
work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/crds-chart.XXXXXX") || refuse "cannot make a working directory"
# Removed at the end, not by a trap: a trap runs last and its status becomes the script's.
done_() { rm -rf "$work" || true; exit "$1"; }
fail() { echo "$*"; done_ 1; }

# The source: every file in the directory, sorted, so the comparison below is over a fixed list.
sources=$(cd "$crds" && find . -maxdepth 1 -type f ! -name '.*' | sed 's|^\./||' | LC_ALL=C sort)
[ -n "$sources" ] || { rm -rf "$work"; refuse "no CRD in $crds -- an empty chart would install nothing and report success"; }
# Anything but a regular file -- a symlink, a fifo -- is refused by name rather than skipped: find
# -type f above does not see it, and a manifest left out of the chart would go unnoticed.
odd=$(cd "$crds" && find . -mindepth 1 -maxdepth 1 ! -type f ! -type d ! -name '.*' | sed 's|^\./||' | LC_ALL=C sort)
[ -z "$odd" ] || fail "${odd//$'\n'/, } is not a regular file in $crds: the git source may apply it, and the chart would not carry it"
others=$(printf '%s\n' "$sources" | grep -v '\.yaml$' || true)
[ -z "$others" ] && [ -z "$(find "$crds" -mindepth 1 -maxdepth 1 -type d)" ] \
  || fail "$crds holds more than *.yaml (${others//$'\n'/, }): the git source applied every manifest there, and crds/*.yaml would leave some out"
files=()
while IFS= read -r f; do files+=("$f"); done <<<"$sources"
n=$(cd "$crds" && cat "${files[@]}" | grep -c '^kind: CustomResourceDefinition$' || true)
[ "$n" -gt 0 ] || fail "no 'kind: CustomResourceDefinition' document in $crds"

base=$(awk '$1 == "version:" { print $2; exit }' "$base_chart" | tr -d "\"'")
version="${base}-g${sha7}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+-g[0-9a-f]{7}$ ]] \
  || fail "'$version' is not <major.minor.patch>-g<sha7> -- $base_chart has version '$base'"

# same <package.tgz> <label>: the package is this version and holds exactly the source's CRDs,
# byte for byte, and helm renders every one of them. Checked on the package before it is pushed
# and on what the registry hands back after, because "helm push exited 0" is a claim about the
# upload, not about what a consumer will pull.
same() {
  local tgz=$1 what=$2 x="$work/x" got listed want rendered
  rm -rf "$x"; mkdir -p "$x"
  tar -xzf "$tgz" -C "$x" 2>/dev/null || { echo "$what: not a readable chart archive"; return 1; }
  got=$(awk '$1 == "version:" { print $2; exit }' "$x/$name/Chart.yaml" 2>/dev/null | tr -d "\"'")
  [ "$got" = "$version" ] || { echo "$what carries version ${got:-<none>}, not $version"; return 1; }
  listed=$(cd "$x/$name" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
  want=$(printf 'Chart.yaml\n'; printf '%s\n' "$sources" | sed 's|^|crds/|')
  want=$(printf '%s\n' "$want" | LC_ALL=C sort)
  [ "$listed" = "$want" ] || { echo "$what: its files differ from kubernetes/config/crd/bases (got: ${listed//$'\n'/ })"; return 1; }
  local f
  for f in "${files[@]}"; do
    cmp -s "$crds/$f" "$x/$name/crds/$f" || { echo "$what: crds/$f differs from kubernetes/config/crd/bases/$f"; return 1; }
  done
  # What a consumer installs is helm's render, not the archive. Argo CD renders with --include-crds.
  helm template "$name" "$tgz" --include-crds >"$work/render" 2>"$work/err" \
    || { echo "$what: helm template failed: $(tail -1 "$work/err")"; return 1; }
  rendered=$(grep -c '^kind: CustomResourceDefinition$' "$work/render" || true)
  [ "$rendered" = "$n" ] || { echo "$what: helm renders $rendered CRDs, the source has $n: $(tail -1 "$work/err")"; return 1; }
}

# The chart, assembled in the working directory from the tree. Chart.yaml is written here: it
# has no other content than the name, the version and where the definitions come from.
src="$work/$name"
mkdir -p "$src/crds"
for f in "${files[@]}"; do cp "$crds/$f" "$src/crds/$f" || fail "cannot copy $f"; done
cat > "$src/Chart.yaml" <<EOF
apiVersion: v2
name: $name
description: The CustomResourceDefinitions of the OpenSandbox controller (BatchSandbox, Pool, SandboxSnapshot), from kubernetes/config/crd/bases at the commit in the version.
type: application
version: $version
home: https://github.com/opensandbox-group/OpenSandbox
sources:
  - https://github.com/Wide-Moat/OpenSandbox/tree/$sha7/kubernetes/config/crd/bases
annotations:
  artifacthub.io/license: Apache-2.0
EOF
helm package "$src" -d "$work" >/dev/null 2>"$work/err" || fail "helm package failed: $(tail -1 "$work/err")"
pkg="$work/$name-$version.tgz"
[ -f "$pkg" ] || fail "helm package wrote no $name-$version.tgz"
same "$pkg" "the package" || done_ 1

# lookup <ref>: prints the digest and returns 0 when the version exists; returns 3 when the
# registry says it is absent; returns 1 with the registry's words on stderr when it could not ask.
lookup() {
  local said rc=0
  said=$(crane digest "$1" 2>&1) || rc=$?
  if [ "$rc" = 0 ] && [[ "$said" =~ (^|$'\n')(sha256:[0-9a-f]{64})$ ]]; then echo "${BASH_REMATCH[2]}"; return 0; fi
  if [ "$rc" != 0 ] && printf '%s' "$said" | grep -qE 'MANIFEST_UNKNOWN|NAME_UNKNOWN'; then return 3; fi
  printf '%s\n' "$said" | tail -1 >&2
  return 1
}

digest=-; pushed=
ref="${repo#oci://}/$name:$version"
if [ -n "$mode" ]; then
  existing=$(lookup "$ref" 2>"$work/err"); rc=$?
  case "$rc" in
    0) if [ "$mode" = --probe ]; then echo "$name $version: already published at $existing"; digest=$existing
       else echo "$name $version: already published, not pushing over it"; fi ;;
    3) if [ "$mode" = --probe ]; then echo "$name $version: absent, would push"
       else helm push "$pkg" "$repo" >/dev/null 2>"$work/err" || fail "$name $version: push failed: $(tail -1 "$work/err")"
            pushed="pushed and "; fi ;;
    *) fail "cannot tell whether $ref exists, so it is not pushed: $(cat "$work/err")" ;;
  esac
fi
if [ "$mode" = --push ]; then
  mkdir -p "$work/pulled"
  helm pull "$repo/$name" --version "$version" -d "$work/pulled" >/dev/null 2>"$work/err" \
    || fail "$name $version: read-back failed: $(tail -1 "$work/err")"
  [ -f "$work/pulled/$name-$version.tgz" ] || fail "$name $version: helm pull wrote no $name-$version.tgz"
  same "$work/pulled/$name-$version.tgz" "the registry's $name:$version" || done_ 1
  digest=$(lookup "$ref" 2>"$work/err") || fail "no digest for $ref: $(cat "$work/err")"
  echo "$name $version: ${pushed}read back, $n CRDs, $digest"
else
  echo "$name $version: $n CRDs, packaged and compared with the source"
fi
echo "$name $version $digest" > "$out" || fail "cannot write $out"
done_ 0
