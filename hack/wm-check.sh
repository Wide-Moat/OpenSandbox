#!/usr/bin/env bash
# Prove that every change this fork carries is still here, still described, and still
# covered by a test.
#
# The failure this exists for is a rebase that drops a change silently. `git rebase`
# resolves a conflict by taking one side, and a hunk whose surroundings moved can end
# up applied to nothing without saying so. The tree then builds, the tests that remain
# pass, and the behaviour is upstream's again.
#
# Three independent statements have to agree, and git is the source of truth for all of
# them rather than a list someone maintains by hand:
#
#   A  ids in the commit messages on this branch
#   B  ids in the NOTICE table
#   C  ids that name a test somewhere in the tree
#
# A == B == C, and each id appears in exactly one commit. Any of the three alone can be
# wrong in a way the other two catch.
set -euo pipefail

cd "$(dirname "$0")/.."

base="${UPSTREAM_BASE:-upstream-base}"
notice="NOTICE-WIDE-MOAT.md"

git rev-parse --verify --quiet "$base" >/dev/null \
  || { echo "no such ref: $base — the tag marking the upstream commit this branch sits on" >&2; exit 2; }
[ -f "$notice" ] || { echo "no $notice" >&2; exit 2; }

# A: from the commit messages. NOT `git log --format=%(trailers)`: git only parses the
# LAST block of a message as trailers, and these commits end with a sign-off block, so
# the parser reports nothing at all. Measured — it printed the sign-off and not this.
mapfile -t commits < <(git log --format='%H' "$base..HEAD")
(( ${#commits[@]} > 0 )) || { echo "no commits between $base and HEAD — nothing to check, which is not the same as clean" >&2; exit 2; }

declare -A seen_in_commit=()
dupes=0
for sha in "${commits[@]}"; do
  while read -r id; do
    [ -n "$id" ] || continue
    if [ -n "${seen_in_commit[$id]:-}" ]; then
      echo "$id is claimed by two commits: ${seen_in_commit[$id]} and $sha" >&2
      dupes=1
    fi
    seen_in_commit["$id"]="$sha"
  done < <(git log -1 --format='%B' "$sha" | sed -n 's/^Wide-Moat-Change: *\(WM-[0-9][0-9]*\).*/\1/p')
done

# LEXICAL sort, and a fixed locale, because `comm` below compares lexically and refuses
# input sorted any other way. Version sort puts WM-10 after WM-2; lexical puts it before.
# With five changes the two orders happen to agree, so this would have started lying at
# the tenth -- and `comm` announcing "file 1 is not in sorted order" under `set -e` would
# kill the script rather than report a drift.
export LC_ALL=C
in_commits=$(printf '%s\n' "${!seen_in_commit[@]}" | sort)
in_notice=$(sed -n 's/^| *\*\*\(WM-[0-9][0-9]*\)\*\*.*/\1/p' "$notice" | sort -u)
in_tests=$(grep -rhoE '(TestWM|test_wm)[0-9]+' \
             --include='*_test.go' --include='test_*.py' . 2>/dev/null \
           | sed -E 's/^(TestWM|test_wm)/WM-/' | sort -u)

fail=0
report() { # report <label> <a> <b> <a-name> <b-name>
  local only
  only=$(comm -23 <(printf '%s\n' "$2") <(printf '%s\n' "$3"))
  if [ -n "$only" ]; then
    echo "in $4 but not in $5: $(echo "$only" | tr '\n' ' ')" >&2
    fail=1
  fi
}

report x "$in_commits" "$in_notice" "the commits" "$notice"
report x "$in_notice" "$in_commits" "$notice" "the commits"
report x "$in_commits" "$in_tests"  "the commits" "the tests"
report x "$in_tests"   "$in_commits" "the tests" "the commits"

n=$(printf '%s\n' "$in_commits" | grep -c . || true)
# A count of zero would otherwise pass every comparison above: three empty sets agree.
(( n > 0 )) || { echo "found no Wide-Moat-Change ids at all — the check scanned nothing" >&2; exit 2; }

if (( fail || dupes )); then
  echo "FAIL: the fork's changes, its NOTICE and its tests do not describe the same set" >&2
  exit 1
fi

echo "OK: $n changes, each in one commit, each in $notice, each with a test"
printf '%s\n' "$in_commits" | sed 's/^/  /'
