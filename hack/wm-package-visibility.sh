#!/usr/bin/env bash
# Does a package this fork published have the visibility it is meant to have?
#
#   hack/wm-package-visibility.sh <owner> <oci-reference> <public|private|internal> [--allow-absent]
#
# <oci-reference> is oci://<host>/<owner path>/<package path>, e.g.
# oci://ghcr.io/wide-moat/charts/opensandbox-crds -> container package charts/opensandbox-crds.
#
# exit 0 the visibility asked for (or, with --allow-absent, not published yet)
# exit 1 another visibility, or absent where a push just happened
# exit 2 could not check: no token, the API refused (401/403/5xx) or answered something
#        unparseable, or a 404 the registry contradicts -- never "fine"
#
# A 404 IS NOT PROOF OF ABSENCE. The packages API answers 404 both for a package that does not
# exist and for one this token may not see. With --allow-absent a 404 is believed only when the
# registry agrees (`crane ls` answering NAME_UNKNOWN); a registry that lists tags means the package
# exists and is hidden from this token.
#
# WHY ASSERT IT AT ALL. A package's visibility is a setting anyone with admin on it can change in
# the web UI, and a consumer's access depends on it: the platform's release reads this chart with
# its own workflow token, which reaches a public package with no per-package grant and a private
# one only through that package's "Manage Actions access" list. So the expected visibility is
# stated by the caller and read back, not assumed.
#
# GH_TOKEN is the token; GITHUB_API_URL the API (api.github.com when unset).
set -uo pipefail
refuse() { echo "REFUSING TO REPORT: $*" >&2; exit 2; }
owner=${1:-}; ref=${2:-}; want=${3:-}; allow=${4:-}
[ -n "$owner" ] || refuse "usage: $0 <owner> <oci-reference> <public|private|internal> [--allow-absent]"
case "$ref" in oci://*/*/?*) ;; *) refuse "reference must be oci://<host>/<owner>/<package path>, got '$ref'" ;; esac
case "$want" in public|private|internal) ;; *) refuse "expected visibility must be public, private or internal, got '$want'" ;; esac
case "$allow" in ''|--allow-absent) ;; *) refuse "the fourth argument must be --allow-absent, got '$allow'" ;; esac
[ -n "${GH_TOKEN:-}" ] || refuse "GH_TOKEN is empty"
command -v curl >/dev/null 2>&1 || refuse "curl is not on PATH"
command -v python3 >/dev/null 2>&1 || refuse "python3 is not on PATH"
if [ "$allow" = --allow-absent ]; then
  command -v crane >/dev/null 2>&1 || refuse "crane is not on PATH -- a 404 cannot be told apart from a hidden package"
fi
pkg=${ref#oci://*/*/}
api=${GITHUB_API_URL:-https://api.github.com}
body=$(mktemp) || refuse "cannot make a temporary file"
code=$(curl -sS --connect-timeout 10 --max-time 30 -o "$body" -w '%{http_code}' \
  -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
  "$api/orgs/$owner/packages/container/${pkg//\//%2F}") || code=000
case "$code" in
  200)
    vis=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("visibility",""))' "$body" 2>/dev/null) \
      || { said=$(head -c 300 "$body"); rm -f "$body"; refuse "$pkg: cannot parse the packages API answer: $said"; }
    rm -f "$body"
    if [ "$vis" = "$want" ]; then echo "$pkg: $vis"; exit 0; fi
    echo "$pkg is ${vis:-<no visibility field>}, expected $want"; exit 1 ;;
  404)
    rm -f "$body"
    [ "$allow" = --allow-absent ] || { echo "$pkg does not exist, yet it was just pushed"; exit 1; }
    lsrc=0; tags=$(crane ls "${ref#oci://}" 2>&1) || lsrc=$?
    if [ "$lsrc" = 0 ]; then
      refuse "$pkg: the registry holds tags for it, yet the packages API answers 404 -- it is hidden from this token"
    elif printf '%s' "$tags" | grep -q NAME_UNKNOWN; then
      echo "$pkg: not published yet"; exit 0
    fi
    refuse "$pkg: the API answers 404 and the registry cannot be asked, so cannot tell whether $pkg exists: $(printf '%s\n' "$tags" | tail -1)" ;;
  *)
    said=$(head -c 300 "$body" 2>/dev/null); rm -f "$body"
    refuse "$pkg: HTTP $code from the packages API -- the visibility cannot be read: $said" ;;
esac
