#!/usr/bin/env bash
# Prove that each WM test still fails against the unmodified upstream tree.
#
# A test that passes on BOTH trees is not a check. It means either that upstream has
# since absorbed the change -- in which case the commit here should be dropped rather
# than carried forever -- or that the test asserts something true regardless, which is
# the shape that goes green while the behaviour it claims to protect is gone.
#
# Method: a worktree at upstream-base, into which ONLY this fork's test files are
# copied. The tests must then fail. They are written to make that possible: literal
# variable names, inspect.signature, dataclasses.fields, reflection -- so that a tree
# without the change still COMPILES them and fails on the answer. A test that fails to
# build proves only that a symbol is missing, and would go green the moment one existed
# with nothing behind it, so a build failure is reported as a defect in the test.
#
# Every WM test DECLARED in this tree (hack/wm-tests.sh, the definition hack/wm-check.sh
# uses too) is then asked for by name on that worktree, and each must fail there -- or
# be argued otherwise in is_guard, is_exempt or is_unported. One that did not run, for
# any reason, fails the gate. And every change named in the commits must have at least
# one test that fails there: a change whose only remaining test is a guard is a change
# nothing proves. hack/wm-gates-selftest.sh checks the classifiers below against outputs
# whose answer is known.
set -euo pipefail

cd "$(dirname "$0")/.."
repo=$(pwd)
base="${UPSTREAM_BASE:-upstream-base}"
# shellcheck source=hack/wm-tests.sh
. hack/wm-tests.sh

# A test that builds the component itself prints this when that build fails, so the
# failure is not read as the test failing on behaviour. Also in the Go tests that do it.
WM_TEST_BUILD_FAILED="WM-TEST-BUILD-FAILED"

# What happened to ONE Go test, read from `go test -json` on stdin:
#   FAILED       its own "fail" event: it executed and failed
#   PASSED       its own "pass" event
#   BUILD_BROKE  no "run" event, and the package did not build -- or the test ran and
#                failed building what it runs, which it says with WM_TEST_BUILD_FAILED
#   NOT_RUN      no "run" event for any other reason, or it skipped itself
#
# Read positively: a test counts as having executed only on its own "run" event. This
# replaces a list of phrases that meant "did not run" -- "no tests to run", "exec format
# error", ... -- which read any phrase nobody had listed yet as a failure upstream, the
# one answer this script must never give for a test that did not run. Measured with
# go1.26: a -run matching nothing prints only a package-level pass; a GOOS=linux binary
# started off Linux prints only a package-level fail; a compile error prints
# "build-fail" and a package "fail" with FailedBuild set. Lines that are not JSON (go's
# own stderr, when merged) are ignored.
go_verdict() { # <exact test name>
  jq -Rrn --arg t "$1" --arg sentinel "$WM_TEST_BUILD_FAILED" '
    [inputs | fromjson? | select(type == "object")] as $ev
    | def has(a): any($ev[]; .Test == $t and .Action == a);
    if has("run") then
      (if has("skip") then "NOT_RUN"
       elif has("fail") and any($ev[]; .Test == $t and .Action == "output"
                                       and ((.Output // "") | contains($sentinel))) then "BUILD_BROKE"
       elif has("fail") then "FAILED"
       elif has("pass") then "PASSED" else "NOT_RUN" end)
    elif any($ev[]; .Action == "build-fail" or ((.FailedBuild // "") != "")) then "BUILD_BROKE"
    else "NOT_RUN" end'
}

# What happened to ONE pytest test function, read from the JUnit report pytest writes
# with --junitxml -- one <testcase> per case, the exception type at the front of each
# <failure message>, <error> for a setup or collection that broke, <skipped> -- not
# from its summary text. A grep over the output misread both ways: an AssertionError
# whose compared text contained "has no attribute" came back BUILD_BROKE, and a missing
# fixture, a ModuleNotFoundError or a changed signature came back FAILED, the one answer
# this script must never give a test that did not reach its assertion.
#
# The run selects with -k, which matches substrings, so only the cases whose name is
# exactly this function (parameters aside) are read. Every case of a parametrised test
# counts: one that fails no longer hides a sibling that passed.
#
#   FAILED       every case failed on behaviour
#   PASSED       every case passed
#   MIXED        some cases passed and some failed -- never an answer a test may give
#   BUILD_BROKE  a case errored in setup, or failed on a missing symbol: an import, a
#                name, a signature, an attribute of anything but None, a field pydantic
#                does not know; or the file did not collect
#   NOT_RUN      no case ran, or a case skipped itself
#
# On stdout: the verdict, then up to three lines saying why.
py_verdict() { # <junit xml> <exact test function name>
  python3 - "$1" "$2" <<'PY'
import re, sys
import xml.etree.ElementTree as ET

path, name = sys.argv[1], sys.argv[2]
try:
    root = ET.parse(path).getroot()
except (OSError, ET.ParseError) as exc:
    print("NOT_RUN"); print(f"no JUnit report: {exc}"); sys.exit(0)

MISSING = re.compile(
    r"^(ImportError|ModuleNotFoundError|NameError|SyntaxError|IndentationError)\b"
    r"|^TypeError: .*(unexpected keyword argument|positional argument|keyword-only argument)"
    r"|^AttributeError: (?!'NoneType' object)"
    r"|Extra inputs are not permitted",
    re.M,
)
cases = list(root.iter("testcase"))
mine = [c for c in cases if re.sub(r"\[.*\Z", "", c.get("name", ""), flags=re.S) == name]
if not mine:
    errors = [e for c in cases for e in c.findall("error")]
    if errors:
        print("BUILD_BROKE"); print((errors[0].get("message") or "").splitlines()[0][:300] if errors[0].get("message") else "collection error")
    else:
        print("NOT_RUN"); print(f"no case named {name} ran")
    sys.exit(0)

outcomes, why = [], []
for case in mine:
    label = case.get("name")
    error, failure, skipped = case.find("error"), case.find("failure"), case.find("skipped")
    if error is not None:
        outcomes.append("broke"); why.append(f"{label}: error: {(error.get('message') or '').strip()[:240]}")
    elif failure is not None:
        text = (failure.get("message") or "") + "\n" + (failure.text or "")
        if MISSING.search(text):
            outcomes.append("broke")
        else:
            outcomes.append("failed")
        why.append(f"{label}: {(failure.get('message') or '').strip().splitlines()[0][:240] if failure.get('message') else 'failed'}")
    elif skipped is not None:
        outcomes.append("skipped"); why.append(f"{label}: skipped: {(skipped.get('message') or '').strip()[:240]}")
    else:
        outcomes.append("passed")

if "broke" in outcomes:
    verdict = "BUILD_BROKE"
elif "skipped" in outcomes:
    verdict = "NOT_RUN"
elif all(o == "failed" for o in outcomes):
    verdict = "FAILED"
elif all(o == "passed" for o in outcomes):
    verdict = "PASSED"
else:
    verdict = "MIXED"
    why.insert(0, f"{outcomes.count('passed')} of {len(outcomes)} cases passed, {outcomes.count('failed')} failed")
print(verdict)
for line in why[:3]:
    print(line)
PY
}

# The changes with no test that fails without them: every id in the first list that is
# not in the second. A change whose tests are all guards, exempt or unported is proved
# by nothing here.
uncovered() { # "<change ids>" "<confirmed ids>" -> the uncovered ids, one per line
  local id
  for id in $1; do
    [[ " $2 " == *" $id "* ]] || echo "$id"
  done
}

# Entry points for hack/wm-gates-selftest.sh, which feeds each classifier outputs it must
# get right. Before any worktree is made.
case "${1:-}" in
  --go-verdict) go_verdict "$2"; exit 0 ;;
  --py-verdict) py_verdict "$2" "$3" | head -1; exit 0 ;;
  --uncovered) uncovered "$2" "$3"; exit 0 ;;
esac

git rev-parse --verify --quiet "$base" >/dev/null \
  || { echo "no such ref: $base" >&2; exit 2; }

# The changes this branch carries, from the commits, as hack/wm-check.sh reads them.
mapfile -t CHANGE_IDS < <(git log --format=%B "$base..HEAD" \
  | sed -n 's/^Wide-Moat-Change: *\(WM-[0-9][0-9]*\).*/\1/p' | LC_ALL=C sort -u)
[ ${#CHANGE_IDS[@]} -gt 0 ] || { echo "FAIL: no Wide-Moat-Change ids between $base and HEAD" >&2; exit 2; }

work=$(mktemp -d)
# A trap, so a failure part-way through does not leave a registered worktree behind on a
# machine that persists between runs. It explicitly preserves the status it was entered
# with: a trap runs last and its own status would otherwise become the script's, which
# is how a sibling check in this organisation once printed PASS and exited 1.
cleanup() {
  local status=$?
  git worktree remove --force "$work/tree" >/dev/null 2>&1 || true
  rm -rf "$work"
  return "$status"
}
trap cleanup EXIT
git worktree add --detach "$work/tree" "$base" >/dev/null 2>&1
up="$work/tree"

# How to run one test on the upstream worktree. Output only; the verdict functions above
# decide what it means.
run_go() { # <module dir> <package> <exact test name>
  # The images are Linux, and several of these files are //go:build linux. Building for
  # the host would silently skip them. Off Linux the test binary then cannot be started,
  # which go_verdict reads as NOT_RUN -- as it must.
  #
  # One package, not ./... : a module-wide run reports twenty packages that do not hold
  # this test, and says nothing more about the one that does.
  ( cd "$up/$1" && GOOS=linux go test -json -count=1 "$2" -run "^$3\$" 2>&1 )
}

# Tests of a path upstream reaches only with netfilter permission. Upstream ignores the
# enforcement variable, attempts its DNS redirect and, off a privileged host, exits there
# -- before anything the test is about. Run anywhere else they skip themselves, which is
# NOT_RUN and fails the gate: "fails without the change" must never mean "died earlier".
# Egress tests only: the component binary is built from the module root.
needs_netfilter() {
  case "$1" in
    TestWM8TheSeedVariableFillsTheVaultAtStartup) return 0 ;;
    *) return 1 ;;
  esac
}
# As root, in a network namespace of its own that disappears with the process: upstream
# installs its redirect there and goes on to where the change would act. The component
# and the test binary are built first, as this user, where the go tool has the network
# and its cache; the test finds the component through WM_EGRESS_BINARY.
run_go_netns() { # <module dir> <package> <exact test name>
  local dir out
  dir=$(mktemp -d "$work/netns.XXXXXX")
  if ! out=$( cd "$up/$1" && GOOS=linux go build -o "$dir/component" . 2>&1 \
                && GOOS=linux go test -c -o "$dir/test" "$2" 2>&1 ); then
    jq -cn --arg o "$out" '{Action: "build-fail", Output: $o}'
    return 0
  fi
  sudo -n env "WM_EGRESS_BINARY=$dir/component" unshare --net -- \
    sh -c 'ip link set lo up && cd "$1" && exec "$2" -test.run "^$3\$" -test.count=1 -test.v=test2json' \
    sh "$up/$1/$2" "$dir/test" "$3" 2>&1 | go tool test2json -t -p "$2" || true
}

run_py() { # <test file, relative to server/> <exact test name> <junit xml>
  ( cd "$up/server" && uv run pytest "$1" -k "$2" -q -p no:cacheprovider --junitxml="$3" ) 2>&1
}

declare -a FAILED_TO_FAIL=() BUILD_BROKE=() CONFIRMED=() GUARDS=() NOT_RUN=() EXEMPT=() UNPORTED=()

# A guard asserts that the DEFAULT is unchanged. Those must PASS on both trees -- that
# is their entire point, and they are the other half of every option this fork adds, so
# they are checked in the other direction rather than skipped.
#
# Named one by one rather than matched by a pattern. A pattern is how this got it wrong
# twice: "without_" swept in test_wm4_..._without_toml_key, which is behavioural (the
# environment must win when TOML says nothing), and every name containing "still" was
# assumed to be about a default. The list is short, it has to change when a test is
# added, and that is the point -- a new test is classified deliberately or the gate
# refuses it.
is_guard() {
  case "$1" in
    TestWM1DialerStillSetsMarkByDefault) return 0 ;;
    TestWM1ReadyStillRequiresNftInSidecarMode) return 0 ;;
    TestWM1ReadyAcceptsDnsNftInSidecarMode) return 0 ;;
    TestWM1TransparentStaysTheDefault) return 0 ;;
    # By default the sidecar still attempts the DNS redirect -- which also proves the log
    # line the external-enforcement test looks for is the one SetupRedirect prints.
    TestWM1SidecarEnforcementStillInstallsTheRedirect) return 0 ;;
    test_wm2_egress_enforcement_defaults_to_sidecar) return 0 ;;
    test_wm2_still_requires_nft_under_sidecar_enforcement) return 0 ;;
    test_wm2_rejects_gvisor_when_no_egress_config_is_given) return 0 ;;
    test_wm2_still_rejects_gvisor_with_sidecar_enforcement) return 0 ;;
    # Docker never tells its sidecar about external enforcement, so its credential proxy
    # must keep upstream's dns+nft requirement whatever [egress] enforcement says, and
    # gVisor with a networkPolicy stays refused there.
    test_wm2_docker_credential_proxy_still_requires_dns_nft_under_external_enforcement) return 0 ;;
    test_wm2_docker_still_rejects_gvisor_with_network_policy_under_external_enforcement) return 0 ;;
    # The gVisor warning is still printed wherever the rejection it predicts still
    # happens: under sidecar enforcement, and on Docker whatever [egress] says.
    test_wm2_still_warns_gvisor_with_sidecar_enforcement) return 0 ;;
    test_wm2_docker_still_warns_gvisor_under_external_enforcement) return 0 ;;
    test_wm4_load_config_without_env_uses_toml_tenants_auth_token) return 0 ;;
    TestWM7StillSleepsWhenSomethingWasSignalled) return 0 ;;
    # No seed given means no variable on the sidecar -- the unchanged default, which must
    # hold on upstream too, where the field does not exist at all.
    test_wm8_no_seed_is_the_default) return 0 ;;
    # WM-8 split the vault's readiness in two for the seed; the API must still wait for
    # mitmdump, as upstream's does.
    TestWM8TheAPIStillWaitsForTheCredentialProxy) return 0 ;;
    # The negative control: a container with no probe serialises with none. That is
    # upstream's behaviour and WM-10 must not change it -- without this test the
    # serialiser could emit a probe unconditionally and the others would pass.
    test_wm10_serialised_probe_is_absent_when_the_container_has_none) return 0 ;;
    # The Windows profile keeps upstream's probe-less main container: execd runs inside
    # the guest, far past the create timeout.
    test_wm10_a_windows_pod_carries_no_execd_probe) return 0 ;;
    # WM-11 narrows exactly one thing. Everything else on execd's port -- above all
    # /proxy/9223/..., which is how the browser reaches Chromium -- and /internal/ on
    # any other port must be forwarded exactly as upstream forwards it; so must a path
    # that stays inside the port it names behind a Docker-shaped endpoint.
    test_wm11_http_proxy_still_forwards_everything_else) return 0 ;;
    test_wm11_websocket_proxy_still_reaches_cdp_through_execd) return 0 ;;
    test_wm11_docker_shaped_endpoints_still_forward_what_stays_inside_the_port) return 0 ;;
    # In runtime-init mode execd serves /internal/init exactly as upstream does.
    TestWM12InternalInitIsStillServedInRuntimeInitMode) return 0 ;;
    *) return 1 ;;
  esac
}

# Tests that assert something true of BOTH trees and are neither a behaviour check nor
# a guard on a default. Each is listed with why, because "it passes upstream too" is
# the shape this script exists to reject, and an exemption has to be argued.
is_exempt() {
  case "$1" in
    # Reads ALLOWED_EGRESS_ENV_VARS and asserts the new variable is absent from it.
    # Upstream has no such variable, so it is absent there too -- trivially true, and
    # still worth keeping: it fails the moment someone adds the variable to that list,
    # which would let a request unfilter its own sandbox.
    test_wm2_the_enforcement_variable_is_not_request_settable) return 0 ;;
    # Asserts that a config with NO [tenants] block still loads when the variable
    # happens to be set. Upstream never reads the variable, so there is nothing there
    # to crash -- it passes on both trees, which is exactly what this script rejects.
    #
    # It is kept because the crash it guards against is introduced BY WM-4, not by
    # upstream: `config.tenants` is None without the block, and assigning
    # `config.tenants.auth_token` raises AttributeError. A single-tenant server would
    # then refuse to start on a perfectly valid configuration, with a message naming
    # neither the variable nor the block. Delete the None check in _apply_raw_env_overrides
    # and this test goes red on OUR tree while still passing on upstream.
    #
    # That is the difference from a behaviour test: it does not describe what WM-4 adds,
    # it describes what WM-4 must not break.
    test_wm4_env_override_without_a_tenants_block_does_not_crash) return 0 ;;
    *) return 1 ;;
  esac
}

# Tests that cannot BUILD on upstream, because they call what the change adds by name,
# and so are not run there at all. Each prints why, and each is backed by a test that
# does run there: a compile error proves only that a symbol is missing, so these check
# this tree's wiring in CI and leave "fails without the change" to their partner.
#
# By name, like is_guard: a new test in one of these files is NOT_RUN until someone
# decides which list it belongs on.
is_unported() {
  case "$1" in
    TestWM1ParseEnforcementDefaultsToSidecar|TestWM1ParseEnforcementAcceptsBothValues|\
    TestWM1ParseEnforcementRefusesAnythingElse|TestWM1EnforcementIsExternalReadsTheEnvironment)
      echo "calls ParseEnforcement/EnforcementIsExternal; upstream: TestWM1UnknownEnforcementIsRefusedAtStartup" ;;
    TestWM1ConfigFromEnvIsWhatTheLauncherTellsMitmdump)
      echo "calls ConfigFromEnv; upstream: TestWM1RegularModeIsSetWhenEnforcementIsExternal" ;;
    TestWM1ShutdownRemovesNoRedirectUnderExternalEnforcement|TestWM1ShutdownStillRemovesBothRedirectsByDefault|\
    TestWM1ExternalEnforcementInstallsNoHTTPRedirect|\
    TestWM1ExternalEnforcementLaunchesARegularProxyAndInstallsNoRedirect|TestWM1TheLauncherIsStillTransparentByDefault)
      echo "swaps the netfilter and launcher call variables; upstream: TestWM1ExternalEnforcementInstallsAndRemovesNoRedirect" ;;
    TestWM6NoNamespacesLeavesTheCacheClusterWide|TestWM6NamespacesAreScopedToWhatWasNamed|\
    TestWM6SeveralNamespacesAndSurroundingSpaceAreAccepted|TestWM6TheFlagReachesTheManagerCache)
      echo "calls applyWatchNamespaces/registerWatchNamespacesFlag; upstream: TestWM6TheFlagIsAppliedAtStartup" ;;
    TestWM8SeedFillsTheVaultBeforeAnyRequest|TestWM8ABadSeedLeavesAnEmptyVaultAndAWorkingSidecar|\
    TestWM8UnsetMeansNoSeeding|TestWM8SeedDoesNotOverwriteAVaultThatAlreadyExists|\
    TestWM8SeedIsRefusedWhereTheAPIWouldBeRefused|\
    TestWM8SeedIsRefusedWithoutTransparentMitmproxy|TestWM8SeedIsJudgedByTheEffectivePolicyIncludingAlwaysAllow|\
    TestWM8ASeedWithAnUnknownFieldIsRefusedAsTheAPIRefusesIt|TestWM8SeedIsRefusedUnderTheRevisionRuntime)
      echo "calls seedCredentialVault; upstream: TestWM8TheSeedVariableFillsTheVaultAtStartup" ;;
    *) return 1 ;;
  esac
}

# record <id> <test> <verdict> <output>: file one verdict under what it means here.
record() {
  local id=$1 what=$2 verdict=$3 out=$4
  if [ "$verdict" = NOT_RUN ]; then
    NOT_RUN+=("$id ($what)")
    echo "--- $id: $what did not RUN on upstream (build tag, a file nobody copied, the name matches nothing, or it skipped itself) ---" >&2
    echo "$out" | head -3 | sed 's/^/    /' >&2 || true
    return 0
  fi

  if [ "$verdict" = MIXED ]; then
    # Some cases of one test passed upstream and some failed: the passing cases check
    # nothing there, whatever list the test is on.
    FAILED_TO_FAIL+=("$id ($what) -- some cases passed on upstream and some failed")
    echo "--- $id: $what gave different answers for its cases on upstream ---" >&2
    echo "$out" | head -4 | sed 's/^/    /' >&2 || true
    return 0
  fi

  if is_exempt "$what"; then
    # Exempt from having to FAIL upstream -- not from having to run and pass. An
    # exemption that ignored the verdict would swallow a genuine breakage: the argued
    # reason is "true on both trees", and a failure means it is no longer true on one.
    if [ "$verdict" = PASSED ]; then
      EXEMPT+=("$id ($what)")
      echo "$id exempt, and argued in is_exempt: $what"
    else
      FAILED_TO_FAIL+=("$id ($what) — exempt, but it did not pass upstream ($verdict), so its stated reason no longer holds")
      echo "--- $id: the exempt $what did not pass on upstream ---" >&2
      echo "$out" | head -3 | sed 's/^/    /' >&2 || true
    fi
    return 0
  fi

  if is_guard "$what"; then
    # Inverted: a guard on the default must PASS against upstream. If it fails there,
    # the "unchanged" behaviour it describes is not upstream's behaviour, so either the
    # guard is wrong or the change is not as conservative as it claims.
    if [ "$verdict" = PASSED ]; then
      GUARDS+=("$id ($what)")
      echo "$id guard holds on upstream, as it must: $what"
    else
      FAILED_TO_FAIL+=("$id ($what) — a guard on the DEFAULT did not pass against upstream ($verdict)")
      echo "--- $id: the guard $what does not hold on unmodified upstream ---" >&2
      echo "$out" | head -3 | sed 's/^/    /' >&2 || true
    fi
    return 0
  fi

  case "$verdict" in
    PASSED)
      FAILED_TO_FAIL+=("$id ($what)")
      echo "--- $id PASSED on unmodified upstream, which it must not ---" >&2
      echo "$out" | tail -5 >&2 || true
      ;;
    BUILD_BROKE)
      BUILD_BROKE+=("$id ($what)")
      echo "--- $id did not COMPILE, or did not reach its assertion, on unmodified upstream ---" >&2
      echo "$out" | head -3 | sed 's/^/    /' >&2 || true
      ;;
    FAILED)
      CONFIRMED+=("$id")
      echo "$id fails on upstream, as it must: $what"
      # `|| true` on every one of these: a pipeline whose last command matches nothing
      # exits 1, and as the last command of a function that status becomes the
      # function's. Under `set -e` the script then dies mid-run having reported success
      # for everything before it.
      echo "$out" | head -2 | sed 's/^/    /' || true
      ;;
    *)
      echo "unknown verdict '$verdict' for $what" >&2
      exit 2
      ;;
  esac
  return 0
}

check_py() { # <id> <test file, relative to server/> <exact test name>
  local xml out verdict
  xml=$(mktemp "$work/junit.XXXXXX")
  run_py "$2" "$3" "$xml" >/dev/null || true
  out=$(py_verdict "$xml" "$3")
  verdict=$(head -1 <<<"$out")
  record "$1" "$3" "$verdict" "$(tail -n +2 <<<"$out")"
}

check_go() { # <id> <module dir> <package> <exact test name>
  local out text
  if needs_netfilter "$4"; then
    out=$(run_go_netns "$2" "$3" "$4")
  else
    out=$(run_go "$2" "$3" "$4" || true)
  fi
  # The printed excerpt is the test's own output, not the JSON around it.
  text=$(jq -Rrj 'fromjson? | select(type == "object" and (.Action == "output" or .Action == "build-output" or .Action == "build-fail")) | .Output // ""' <<<"$out" \
         | grep -iE 'FAIL|Error|expected|actual|assert|skip|build|undefined' || true)
  record "$1" "$4" "$(go_verdict "$4" <<<"$out")" "$text"
}

copy() { # <path relative to repo root>
  mkdir -p "$up/$(dirname "$1")"
  cp "$repo/$1" "$up/$1"
}

# The test files that run on upstream. Anything declaring a WM test and not copied here
# comes back NOT_RUN unless is_unported says why it cannot build there.
#
# Go: WM-1 in four packages and the component itself -- which the process-level tests
# build and start, so on upstream they compile and fail on what the process does -- plus
# WM-7's stop hook, WM-8's seed through the process and the API's wait, WM-6's flag, and
# WM-12 in execd's router.
copy components/egress/pkg/dnsproxy/enforcement_linux_test.go
copy components/egress/pkg/credentialvault/enforcement_test.go
copy components/egress/pkg/mitmproxy/regular_mode_test.go
copy components/egress/pkg/mitmproxy/regular_mode_reflect_test.go
copy components/egress/enforcement_startup_test.go
copy components/egress/credential_vault_seed_startup_test.go
copy components/egress/credential_vault_api_wait_test.go
copy components/egress/cleanup_sleep_test.go
copy kubernetes/cmd/controller/watch_namespaces_flag_test.go
copy components/execd/pkg/web/internal_init_test.go
# Python: WM-2, WM-4, WM-8, WM-10, WM-11.
copy server/tests/test_validators.py
copy server/tests/test_config.py
copy server/tests/test_runtime_resolver.py
copy server/tests/test_docker_service.py
copy server/tests/test_credential_proxy_seed.py
copy server/tests/k8s/test_egress_helper.py
copy server/tests/k8s/test_create_path_egress.py
copy server/tests/k8s/test_sandbox_readiness_probe.py
copy server/tests/test_proxy_execd_internal.py

# Module and package of a Go test file, from the nearest go.mod above it.
go_package() { # <path> -> "<module dir> <package>"
  local dir mod rel
  dir=$(dirname "$1")
  mod=$dir
  while [ ! -f "$repo/$mod/go.mod" ]; do
    [ "$mod" != "." ] || { echo "no go.mod above $1" >&2; exit 2; }
    mod=$(dirname "$mod")
  done
  rel=${dir#"$mod"}
  rel=${rel#/}
  if [ -n "$rel" ]; then echo "$mod ./$rel"; else echo "$mod ."; fi
}

( cd "$up/server" && uv sync --quiet ) >/dev/null 2>&1

go_total=0
py_total=0
while read -r id path name; do
  [ -n "$name" ] || continue
  case "$path" in
    *_test.go)
      go_total=$((go_total + 1))
      if reason=$(is_unported "$name"); then
        UNPORTED+=("$id ($name): $reason")
        continue
      fi
      read -r mod pkg < <(go_package "$path")
      check_go "$id" "$mod" "$pkg" "$name"
      ;;
    server/tests/*.py)
      py_total=$((py_total + 1))
      check_py "$id" "${path#server/}" "$name"
      ;;
    *)
      # Declared, so hack/wm-check.sh counts it -- but this gate runs pytest only in
      # server/, and a test it cannot run proves nothing.
      NOT_RUN+=("$id ($name) in $path, where this gate runs no tests")
      echo "--- $id: $name is declared in $path, where this gate runs no tests ---" >&2
      ;;
  esac
done < <(wm_tests "$repo")
# Discovery that finds nothing would pass every check below by checking nothing.
[ "$go_total" -gt 0 ] || { echo "FAIL: found no Go WM tests in this tree" >&2; exit 2; }
[ "$py_total" -gt 0 ] || { echo "FAIL: found no Python WM tests in this tree" >&2; exit 2; }

# Every change must have at least one test that fails without it.
mapfile -t UNCOVERED < <(uncovered "${CHANGE_IDS[*]}" "${CONFIRMED[*]:-}")

echo
if [ ${#UNPORTED[@]} -gt 0 ]; then
  echo "${#UNPORTED[@]} not run upstream, each argued in is_unported:"
  printf '  %s\n' "${UNPORTED[@]}"
fi
if [ ${#BUILD_BROKE[@]} -gt 0 ]; then
  echo "FAIL: these did not compile against upstream, or did not reach their assertion, so they test a symbol rather than behaviour:" >&2
  printf '  %s\n' "${BUILD_BROKE[@]}" >&2
fi
if [ ${#FAILED_TO_FAIL[@]} -gt 0 ]; then
  echo "FAIL: these passed against upstream, so they check nothing -- or the change is now upstream and the commit should be dropped:" >&2
  printf '  %s\n' "${FAILED_TO_FAIL[@]}" >&2
fi
if [ ${#NOT_RUN[@]} -gt 0 ]; then
  echo "FAIL: these never executed, so they prove nothing either way:" >&2
  printf '  %s\n' "${NOT_RUN[@]}" >&2
fi
if [ ${#UNCOVERED[@]} -gt 0 ]; then
  echo "FAIL: these changes have no test that fails without them: ${UNCOVERED[*]}" >&2
fi
if [ ${#BUILD_BROKE[@]} -gt 0 ] || [ ${#FAILED_TO_FAIL[@]} -gt 0 ] || [ ${#NOT_RUN[@]} -gt 0 ] \
   || [ ${#UNCOVERED[@]} -gt 0 ]; then
  exit 1
fi
ids=$(printf '%s\n' "${CONFIRMED[@]}" | sort -u | tr '\n' ' ')
echo "OK: ${#CONFIRMED[@]} tests fail against unmodified upstream, covering every change: $ids"
echo "    and ${#GUARDS[@]} guards on the unchanged default hold there, as they must"
[ ${#EXEMPT[@]} -eq 0 ] || echo "    ${#EXEMPT[@]} exempt: ${EXEMPT[*]}"
