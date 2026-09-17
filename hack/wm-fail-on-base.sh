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
set -euo pipefail

cd "$(dirname "$0")/.."
repo=$(pwd)
base="${UPSTREAM_BASE:-upstream-base}"

git rev-parse --verify --quiet "$base" >/dev/null \
  || { echo "no such ref: $base" >&2; exit 2; }

work=$(mktemp -d)
# A trap, so a failure part-way through does not leave a registered worktree behind on a
# machine that persists between runs. It explicitly preserves the status it was entered
# with: a trap runs last and its own status would otherwise become the script's, which
# is how a sibling check in this organisation once printed PASS and exited 1.
cleanup() {
  local status=$?
  git worktree remove --force "$work" >/dev/null 2>&1 || true
  rm -rf "$work"
  return "$status"
}
trap cleanup EXIT
git worktree add --detach "$work" "$base" >/dev/null 2>&1

# id -> the test files that cover it, and how to run them.
run_go() { # <dir> <package> <exact test name>
  # The images are Linux, and several of these files are //go:build linux. Building for
  # the host would silently skip them -- "no tests to run", exit 0 -- which this script
  # would otherwise read as the change already being upstream.
  #
  # One package, not ./... : with the whole module, `go test` prints "no tests to run"
  # for each of the twenty packages that do not hold this test, and the phrase then
  # says nothing about whether the test itself ran. Measured -- it made a healthy run
  # look skipped, and a skipped one look healthy.
  ( cd "$work/$1" && GOOS=linux go test "$2" -run "^$3\$" ) 2>&1
}
run_py() { # <exact test name>
  ( cd "$work/server" && uv run pytest tests/ -k "$1" -q ) 2>&1
}

# Every test function matching the id, one at a time.
#
# Running a whole package at once hides the thing this script exists to find: with
# `-run TestWM1` a single genuine failure makes the package red, and a sibling that
# passed -- the vacuous test, or the one whose change upstream has absorbed -- is
# invisible in that result. Measured: a deliberately empty TestWM1Vacuous went
# undetected until this was split.
names_py() { # <id prefix>
  grep -rhoE "def (${1}[A-Za-z0-9_]*)\(" "$work/server/tests" --include='*.py' 2>/dev/null \
    | sed -E 's/^def //; s/\($//' | sort -u
}

declare -a FAILED_TO_FAIL=() BUILD_BROKE=() CONFIRMED=() GUARDS=() NOT_RUN=() EXEMPT=()

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
    test_wm2_egress_enforcement_defaults_to_sidecar) return 0 ;;
    test_wm2_still_requires_nft_under_sidecar_enforcement) return 0 ;;
    test_wm2_rejects_gvisor_when_no_egress_config_is_given) return 0 ;;
    test_wm2_still_rejects_gvisor_with_sidecar_enforcement) return 0 ;;
    test_wm4_load_config_without_env_uses_toml_tenants_auth_token) return 0 ;;
    TestWM7StillSleepsWhenSomethingWasSignalled) return 0 ;;
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

check() { # <id> <description> <command...>
  local id=$1 what=$2; shift 2
  local out status
  set +e
  out=$("$@")
  status=$?
  set -e
  # A test that did not execute proves nothing, and exits 0 while saying so. Counting
  # that as "passed" is how a check stops being one -- on macOS the //go:build linux
  # tests never ran, and the gate read their absence as the change already being
  # upstream.
  #
  # The match has to be careful. `go test ./...` prints "no tests to run" for every
  # OTHER package in the module, twenty of them, even when the target package ran the
  # test and failed. Looking for the phrase anywhere would therefore flag every healthy
  # run. Only a report with no result line at all -- no ok/FAIL for a package that
  # actually ran something -- means it did not execute.
  if echo "$out" | grep -qE 'no tests to run|no test files|no tests ran|matched no tests'; then
    NOT_RUN+=("$id ($what)")
    echo "--- $id: $what did not RUN on upstream (build tag, or the name matches nothing) ---" >&2
    return 0
  fi

  if is_exempt "$what"; then
    # Exempt from having to FAIL upstream -- not from having to run and pass. An
    # exemption that ignored the status would swallow a genuine breakage: the argued
    # reason is "true on both trees", and a nonzero status means it is no longer true
    # on one of them.
    if [ "$status" -eq 0 ]; then
      EXEMPT+=("$id ($what)")
      echo "$id exempt, and argued in is_exempt: $what"
    else
      FAILED_TO_FAIL+=("$id ($what) — exempt, but it FAILED upstream, so its stated reason no longer holds")
      echo "--- $id: the exempt $what failed on upstream ---" >&2
      echo "$out" | grep -iE 'FAIL:|Error:|assert' | head -3 >&2 || true
    fi
    return 0
  fi

  if is_guard "$what"; then
    # Inverted: a guard on the default must PASS against upstream. If it fails there,
    # the "unchanged" behaviour it describes is not upstream's behaviour, so either the
    # guard is wrong or the change is not as conservative as it claims.
    if [ "$status" -eq 0 ]; then
      GUARDS+=("$id ($what)")
      echo "$id guard holds on upstream, as it must: $what"
    else
      FAILED_TO_FAIL+=("$id ($what) — a guard on the DEFAULT failed against upstream")
      echo "--- $id: the guard $what does not hold on unmodified upstream ---" >&2
      echo "$out" | grep -iE 'FAIL:|Error:|assert' | head -3 >&2 || true
    fi
    return 0
  fi
  if [ "$status" -eq 0 ]; then
    FAILED_TO_FAIL+=("$id ($what)")
    echo "--- $id PASSED on unmodified upstream, which it must not ---" >&2
    echo "$out" | tail -5 >&2 || true
  elif echo "$out" | grep -qiE 'build failed|undefined:|unexpected keyword|cannot find|SyntaxError|ImportError|has no attribute'; then
    BUILD_BROKE+=("$id ($what)")
    echo "--- $id did not COMPILE on unmodified upstream ---" >&2
    echo "$out" | grep -iE 'build failed|undefined:|unexpected keyword|cannot find|SyntaxError|ImportError|has no attribute' | head -3 >&2 || true
  else
    CONFIRMED+=("$id")
    echo "$id fails on upstream, as it must:"
    # `|| true` on every one of these: grep exits 1 when it matches nothing, and as the
    # last command of a function that status becomes the function's. Under `set -e` the
    # script then dies mid-run having reported success for everything before it -- which
    # is exactly how this was found, stopping silently after the first WM-2 test.
    echo "$out" | grep -iE 'FAIL:|Error:|assert|Failed:' | head -2 | sed 's/^/    /' || true
  fi
  return 0
}

copy() { # <path relative to repo root>
  mkdir -p "$work/$(dirname "$1")"
  cp "$repo/$1" "$work/$1"
}

# WM-1 — egress, four packages
copy components/egress/pkg/dnsproxy/enforcement_linux_test.go
copy components/egress/pkg/credentialvault/enforcement_test.go
copy components/egress/pkg/mitmproxy/regular_mode_test.go
copy components/egress/pkg/mitmproxy/regular_mode_reflect_test.go
for pkg_and_name in \
  "./pkg/dnsproxy TestWM1DialerSetsNoMarkWhenEnforcementIsExternal" \
  "./pkg/dnsproxy TestWM1DialerStillSetsMarkByDefault" \
  "./pkg/credentialvault TestWM1ReadyAcceptsDnsOnlyWhenEnforcementIsExternal" \
  "./pkg/credentialvault TestWM1ReadyStillRequiresNftInSidecarMode" \
  "./pkg/credentialvault TestWM1ReadyAcceptsDnsNftInSidecarMode" \
  "./pkg/mitmproxy TestWM1RegularModeIsSetWhenEnforcementIsExternal" \
  "./pkg/mitmproxy TestWM1TransparentStaysTheDefault"; do
  set -- $pkg_and_name
  check WM-1 "$2" run_go components/egress "$1" "$2"
done

# WM-2 and WM-4 — server
copy server/tests/test_validators.py
copy server/tests/test_config.py
copy server/tests/k8s/test_egress_helper.py
( cd "$work/server" && uv sync --quiet ) >/dev/null 2>&1
for name in $(names_py test_wm2); do
  check WM-2 "$name" run_py "$name"
done
for name in $(names_py test_wm4); do
  check WM-4 "$name" run_py "$name"
done

# WM-6 — controller. Only the behavioural half: the unit tests name the helper the
# change adds, which on this tree is a compile error rather than a wrong answer.
copy kubernetes/cmd/controller/watch_namespaces_flag_test.go
check WM-6 TestWM6TheFlagIsOffered run_go kubernetes ./cmd/controller TestWM6TheFlagIsOffered

# WM-7 — the stop hook
copy components/egress/cleanup_sleep_test.go
check WM-7 TestWM7NoSleepWhenNothingWasSignalled run_go components/egress . TestWM7NoSleepWhenNothingWasSignalled
check WM-7 TestWM7StillSleepsWhenSomethingWasSignalled run_go components/egress . TestWM7StillSleepsWhenSomethingWasSignalled

# WM-8 — pause must preserve tasks when snapshots cannot be configured.
# The test uses reflection so upstream executes behavior instead of failing to compile.
copy kubernetes/internal/controller/batchsandbox_pause_preflight_test.go
check WM-8 TestWM8PausePreflight_MissingRegistryPreservesRunningTask run_go kubernetes ./internal/controller TestWM8PausePreflight_MissingRegistryPreservesRunningTask

echo
if [ ${#BUILD_BROKE[@]} -gt 0 ]; then
  echo "FAIL: these did not compile against upstream, so they test a symbol rather than behaviour:" >&2
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
if [ ${#BUILD_BROKE[@]} -gt 0 ] || [ ${#FAILED_TO_FAIL[@]} -gt 0 ] || [ ${#NOT_RUN[@]} -gt 0 ]; then
  exit 1
fi
# Zero confirmed would otherwise read as success, having checked nothing at all.
[ ${#CONFIRMED[@]} -gt 0 ] || { echo "FAIL: no change was checked" >&2; exit 2; }
ids=$(printf '%s\n' "${CONFIRMED[@]}" | sort -u | tr '\n' ' ')
echo "OK: ${#CONFIRMED[@]} tests fail against unmodified upstream, covering: $ids"
echo "    and ${#GUARDS[@]} guards on the unchanged default hold there, as they must"
[ ${#EXEMPT[@]} -eq 0 ] || echo "    ${#EXEMPT[@]} exempt: ${EXEMPT[*]}"
