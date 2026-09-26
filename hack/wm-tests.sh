# shellcheck shell=bash
# Sourced, not run: the definitions both gates share -- what a WM test is, and how a
# commit names the change it belongs to.
#
# hack/wm-check.sh needs the set of ids that have a test; hack/wm-fail-on-base.sh needs
# every test to run against upstream. They used to find those with two different
# patterns over two different scopes -- one over the whole tree, one over server/tests
# only -- so a Python test in components/egress/tests satisfied the first and was never
# run by the second. Now both read this, and hack/wm-gates-selftest.sh checks it.
#
# A WM test is a DECLARATION, not a mention: `func TestWM<n>...(` at the start of a line
# in a *_test.go file, or `def test_wm<n>...(` (async def included) after nothing but
# indentation in a test_*.py file. A comment or a string naming a test that has since
# been deleted would otherwise keep its id alive.
#
# The working tree, not `git grep`: a test file not yet committed is exactly the one a
# local run must not miss. Virtual environments and vendored modules are skipped.

WM_TEST_DECLARATION='^(func TestWM[0-9]+[A-Za-z0-9_]*\(|[[:space:]]*(async[[:space:]]+)?def test_wm[0-9]+[A-Za-z0-9_]*\()'

# wm_tests [root]: "<id> <path> <name>" for every WM test declared under root (default:
# the current directory), one per line, sorted. Paths are relative to root.
wm_tests() {
  local root=${1:-.}
  (
    cd "$root" || exit 2
    grep -rnE --include='*_test.go' --include='test_*.py' \
      --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=vendor \
      "$WM_TEST_DECLARATION" . || true
  ) | awk '{
      path = $0; sub(/:[0-9]+:.*/, "", path); sub(/^\.\//, "", path)
      line = $0; sub(/^[^:]*:[0-9]+:/, "", line)
      if (!match(line, /(TestWM|test_wm)[0-9]+[A-Za-z0-9_]*/)) next
      name = substr(line, RSTART, RLENGTH)
      match(name, /[0-9]+/)
      print "WM-" substr(name, RSTART, RLENGTH), path, name
    }' | LC_ALL=C sort -u
}

# A commit names its change with a trailer: `Wide-Moat-Change: WM-<n>`, or
# `Wide-Moat-Change: none (<why>)` for a product commit that belongs to no change.
# hack/wm-check.sh reads it per commit, to refuse an id claimed twice and a product
# commit that names nothing; hack/wm-fail-on-base.sh reads the set, to require a test
# that fails upstream for every id. Parsed here once, so that the two cannot drift into
# accepting an id the other never asks about. Read from the message body, not with
# `git log --format=%(trailers)`: git parses only a message's LAST block as trailers, and
# these commits end with a sign-off block, so that printed the sign-off and not this.
WM_CHANGE_TRAILER='^Wide-Moat-Change: *(WM-[0-9]+|none \(.+\))'

# wm_change_ids: the WM-<n> ids the commit message(s) on stdin name, one per line, in
# the order they appear.
wm_change_ids() {
  sed -n 's/^Wide-Moat-Change: *\(WM-[0-9][0-9]*\).*/\1/p'
}

# wm_names_a_change: true when the commit message on stdin carries the trailer, with an
# id or with `none (<why>)`.
wm_names_a_change() {
  grep -qE "$WM_CHANGE_TRAILER"
}
