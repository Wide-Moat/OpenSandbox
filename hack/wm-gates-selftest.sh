#!/usr/bin/env bash
# Run this fork's two gates against inputs whose answer is known, and fail if either
# gives the wrong one.
#
# A gate is code, and it has been wrong in exactly the way that keeps a build green:
# wm-check counted a test id from a comment, and wm-fail-on-base counted a test that
# never ran -- an empty pytest selection, a Linux test binary on a Mac, a missing
# fixture -- as failing on upstream. Each fix was proved on a known-bad input once, by
# hand, and nothing kept it proved after the next edit. This does, in CI, beside the
# gates themselves.
#
#   wm-check.sh          fixture repositories it must accept, and ones it must refuse
#   wm_tests             the discovery both gates share, on declarations it must find
#   go_verdict           real `go test -json` output from a scratch module, one case per
#                        way a test can fail, pass, not build or not run
#   py_verdict           real pytest JUnit reports from a scratch file, the same cases
#                        and the ones only pytest has
#   uncovered            the per-change coverage the gate requires
set -euo pipefail

cd "$(dirname "$0")/.."
repo=$(pwd)
work=$(mktemp -d)
cleanup() {
  local status=$?
  rm -rf "$work"
  return "$status"
}
trap cleanup EXIT

cases=0
failures=0
expect() { # <label> <want> <got>
  cases=$((cases + 1))
  if [ "$2" = "$3" ]; then
    echo "ok   $1: $3"
  else
    echo "FAIL $1: want $2, got $3" >&2
    failures=$((failures + 1))
  fi
}

# ─── wm-check.sh ──────────────────────────────────────────────────────────────
fixture=$work/check
commit() { # <message...>: commit whatever is staged in the fixture
  git -C "$fixture" -c user.name=selftest -c user.email=selftest@invalid commit -q --allow-empty "$@"
}
new_fixture() { # a repository with one change, WM-1, described and tested
  rm -rf "$fixture"
  mkdir -p "$fixture/hack"
  cp "$repo/hack/wm-check.sh" "$repo/hack/wm-tests.sh" "$fixture/hack/"
  git -C "$fixture" init -q
  commit -m base
  git -C "$fixture" tag base
  printf '| id |\n|---|\n| **WM-1** | a change |\n' > "$fixture/NOTICE-WIDE-MOAT.md"
  mkdir -p "$fixture/tests"
  printf 'def test_wm1_real():\n    pass\n' > "$fixture/tests/test_a.py"
  git -C "$fixture" add NOTICE-WIDE-MOAT.md tests/test_a.py
  commit -m "a change" -m "Wide-Moat-Change: WM-1"
}
verdict() { # -> accepted | refused
  if (cd "$fixture" && UPSTREAM_BASE=base hack/wm-check.sh >/dev/null 2>&1); then
    echo accepted
  else
    echo refused
  fi
}
check_with() { # <file> <contents> -> accepted | refused, with that test file instead
  new_fixture
  rm -rf "$fixture/tests"
  mkdir -p "$fixture/$(dirname "$1")"
  printf '%s\n' "$2" > "$fixture/$1"
  verdict
}
expect "wm-check: a Python test" accepted \
  "$(check_with tests/test_a.py 'def test_wm1_real():')"
expect "wm-check: an indented async Python test" accepted \
  "$(check_with tests/test_a.py '    async def test_wm1_real():')"
expect "wm-check: a Go test" accepted \
  "$(check_with pkg/a_test.go 'func TestWM1Real(t *testing.T) {}')"
expect "wm-check: a Python test named only in a comment" refused \
  "$(check_with tests/test_a.py '#   def test_wm1_real(wired, auth_headers):')"
expect "wm-check: a test mentioned in prose" refused \
  "$(check_with tests/test_a.py '# see test_wm1_real')"
expect "wm-check: a Go test named only in a comment" refused \
  "$(check_with pkg/a_test.go '// func TestWM1Real(t *testing.T) {}')"

new_fixture
printf 'x = 1\n' > "$fixture/product.py"
git -C "$fixture" add product.py
commit -m "a review fix, committed beside its change"
expect "wm-check: a product commit that names no change" refused "$(verdict)"

new_fixture
printf 'x = 1\n' > "$fixture/product.py"
git -C "$fixture" add product.py
commit -m "an upstream flake fix" -m "Wide-Moat-Change: none (fixes an upstream test)"
expect "wm-check: a product commit that says it belongs to none" accepted "$(verdict)"

new_fixture
printf '# gate\n' > "$fixture/hack/extra.sh"
git -C "$fixture" add hack/extra.sh
commit -m "gate tooling"
expect "wm-check: a commit to the fork's own files that names no change" accepted "$(verdict)"

new_fixture
printf 'x = 1\n' > "$fixture/product.py"
git -C "$fixture" add product.py
commit -m "more of the same change" -m "Wide-Moat-Change: WM-1"
expect "wm-check: one change claimed by two commits" refused "$(verdict)"

new_fixture
printf '| **WM-2** | another |\n' >> "$fixture/NOTICE-WIDE-MOAT.md"
git -C "$fixture" add NOTICE-WIDE-MOAT.md
commit -m "describe a change that is not here"
expect "wm-check: a change only in the NOTICE" refused "$(verdict)"

# ─── wm_tests: the discovery both gates share ─────────────────────────────────
tree=$work/discover
mkdir -p "$tree/server/tests" "$tree/components/egress/tests" "$tree/pkg"
printf 'class T:\n    def test_wm3_in_a_class(self):\n        pass\n' > "$tree/server/tests/test_s.py"
printf 'def test_wm4_outside_server():\n    pass\n' > "$tree/components/egress/tests/test_e.py"
printf 'def test_wm5_in_a_helper():\n    pass\n' > "$tree/server/tests/helpers.py"
printf 'func TestWM6Go(t *testing.T) {}\n' > "$tree/pkg/a_test.go"
discovered=$(. "$repo/hack/wm-tests.sh" && wm_tests "$tree" | awk '{print $3}' | tr '\n' ' ')
# A test outside server/tests is found, so hack/wm-fail-on-base.sh reports it as one it
# cannot run instead of never seeing it; a def in a file pytest would not collect is not.
expect "wm_tests: declarations in and out of server/tests, not in helpers" \
  "test_wm3_in_a_class test_wm4_outside_server TestWM6Go " "$discovered"

# ─── go_verdict ───────────────────────────────────────────────────────────────
mod=$work/gomod
mkdir -p "$mod"
printf 'module selftest\n\ngo 1.22\n' > "$mod/go.mod"
cat > "$mod/a_test.go" <<'EOF'
package selftest

import "testing"

func TestPass(t *testing.T) {}
func TestFail(t *testing.T) { t.Fatal("fails") }
func TestSkip(t *testing.T) { t.Skip("skips") }
func TestBuildsWhatItRuns(t *testing.T) {
	t.Fatalf("WM-TEST-BUILD-FAILED: building the component: exit status 1")
}
EOF
go_run() { # <go test args...> -> verdict for the test named by the last arg's ^name$
  local name=$1; shift
  (cd "$mod" && CGO_ENABLED=0 go test -json -count=1 "$@" -run "^${name}\$" . 2>&1 || true) \
    | "$repo/hack/wm-fail-on-base.sh" --go-verdict "$name"
}
expect "go: a failing test" FAILED "$(go_run TestFail)"
expect "go: a passing test" PASSED "$(go_run TestPass)"
expect "go: a test that skips itself" NOT_RUN "$(go_run TestSkip)"
expect "go: a name that matches nothing" NOT_RUN "$(go_run TestNothing)"
expect "go: a test whose own build of the component failed" BUILD_BROKE "$(go_run TestBuildsWhatItRuns)"
# A binary this machine cannot execute. Every Go check on a Mac used to come back
# "fails on upstream" this way, having executed nothing.
other=linux
[ "$(go env GOOS)" != linux ] || other=darwin
expect "go: a test binary for another OS" NOT_RUN "$(GOOS=$other go_run TestFail)"
echo 'func TestBroken(t *testing.T) { undefinedHere() }' >> "$mod/a_test.go"
expect "go: a package that does not build" BUILD_BROKE "$(go_run TestPass)"

# ─── py_verdict ───────────────────────────────────────────────────────────────
# Real JUnit reports, from pytest as the gate runs it: one file, -k <name>.
pydir=$work/py
mkdir -p "$pydir"
cat > "$pydir/test_cases.py" <<'EOF'
import importlib

import pytest


def test_passes():
    assert True


def test_fails():
    assert "a" == "b"


def test_fails_on_text_that_names_an_attribute():
    assert "module 'x' has no attribute 'y'" == ""


def test_fails_on_none():
    config = None
    config.auth_token


def test_needs_a_fixture_nobody_defines(no_such_fixture):
    assert False


def test_imports_a_module_that_is_not_there():
    importlib.import_module("no_such_module_anywhere")


def f(a, b):
    return a + b


def test_calls_with_the_wrong_arity():
    f(1)


@pytest.mark.parametrize("value", [1, 2])
def test_mixed(value):
    assert value == 1


@pytest.mark.parametrize("value", [1, 2])
def test_all_cases_fail(value):
    assert value == 3


def test_skips():
    pytest.skip("skips")


def test_sibling():
    assert False


def test_sibling_longer():
    assert True
EOF
printf 'import no_such_module_anywhere\n\ndef test_in_a_broken_file():\n    pass\n' > "$pydir/test_broken.py"
py_run() { # <file> <name> -> verdict
  local xml=$pydir/$2.xml
  (cd "$repo/server" && uv run --quiet pytest "$pydir/$1" -k "$2" -q -p no:cacheprovider --junitxml="$xml" \
     >/dev/null 2>&1 || true)
  "$repo/hack/wm-fail-on-base.sh" --py-verdict "$xml" "$2"
}
expect "py: a passing test" PASSED "$(py_run test_cases.py test_passes)"
expect "py: a failing assertion" FAILED "$(py_run test_cases.py test_fails)"
expect "py: an assertion whose text names an attribute" FAILED \
  "$(py_run test_cases.py test_fails_on_text_that_names_an_attribute)"
expect "py: an attribute read from None, which is behaviour" FAILED "$(py_run test_cases.py test_fails_on_none)"
expect "py: a fixture that does not exist" BUILD_BROKE "$(py_run test_cases.py test_needs_a_fixture_nobody_defines)"
expect "py: a module that is not there, imported in the test" BUILD_BROKE \
  "$(py_run test_cases.py test_imports_a_module_that_is_not_there)"
expect "py: a call with the wrong arity" BUILD_BROKE "$(py_run test_cases.py test_calls_with_the_wrong_arity)"
expect "py: one case passes and one fails" MIXED "$(py_run test_cases.py test_mixed)"
expect "py: every case fails" FAILED "$(py_run test_cases.py test_all_cases_fail)"
expect "py: a test that skips itself" NOT_RUN "$(py_run test_cases.py test_skips)"
# -k matches substrings: test_sibling selects test_sibling_longer too, which passes and
# must not hide, or be hidden by, the one that was asked for.
expect "py: a name that is a prefix of another test's" FAILED "$(py_run test_cases.py test_sibling)"
expect "py: a name that matches nothing" NOT_RUN "$(py_run test_cases.py test_nothing_by_this_name)"
expect "py: a file that does not import" BUILD_BROKE "$(py_run test_broken.py test_in_a_broken_file)"
expect "py: no report at all" NOT_RUN \
  "$("$repo/hack/wm-fail-on-base.sh" --py-verdict "$pydir/absent.xml" test_passes)"

# ─── uncovered ────────────────────────────────────────────────────────────────
expect "coverage: a change whose only test passes upstream as a guard" WM-7 \
  "$("$repo/hack/wm-fail-on-base.sh" --uncovered "WM-1 WM-7" "WM-1 WM-1")"
expect "coverage: every change has a failing test" "" \
  "$("$repo/hack/wm-fail-on-base.sh" --uncovered "WM-1 WM-7" "WM-7 WM-1")"

echo
[ "$cases" -gt 0 ] || { echo "FAIL: no case ran" >&2; exit 2; }
if [ "$failures" -gt 0 ]; then
  echo "FAIL: $failures of $cases gate self-test cases gave the wrong answer" >&2
  exit 1
fi
echo "OK: $cases gate self-test cases, each answered as it must be"
