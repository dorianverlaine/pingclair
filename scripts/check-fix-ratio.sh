#!/usr/bin/env bash

set -Eeuo pipefail

# 📉 Measure how much of the recent work is repair rather than progress.
#
# The plain-language idea: if most of what a repository commits is fixing
# what it committed last week, then adding more features is making the debt
# bigger, not smaller. Counting `fix(` subjects over a fixed window turns
# that feeling into a number a machine can act on.
#
# The window is the last 30 non-merge commits, and the ceiling is 18 of them
# (60 %). Both are deliberately crude — the point is a brake with a fixed
# position, not a metric to tune. All-time this repository sits at 95 fixes
# to 57 features; over the most recent 100 commits it is 39 to 12, which is
# the trend the brake exists to stop.
readonly window=30
readonly ceiling=18

# 🧮 `git rev-list --count HEAD` is cheap and, on a shallow clone, honest:
# it reports what was actually fetched. Counting fixes over 12 commits and
# comparing against a ceiling calibrated for 30 would make the ratio look
# artificially healthy, so a short history fails loudly instead. CI must
# fetch deep enough (see .github/workflows/ci.yml).
available="$(git rev-list --count --no-merges HEAD)"
if [[ "${available}" -lt "${window}" ]]; then
    echo "::error::only ${available} non-merge commit(s) available, need ${window} — this is a shallow clone; fetch more history" >&2
    exit 1
fi

# 🎯 Anchored at the start of the subject and matched literally, so a fix
# is only what the house style spells as a fix: emoji, space, `fix`, then an
# optional scope. `revert(` and `test(` are not fixes and must not inflate
# the count — stabilization work is supposed to be allowed.
fixes="$(git log --no-merges -n "${window}" --format='%s' \
    | grep -cE '^[^[:space:]]+ fix(\([^)]*\))?: ' || true)"

# 🧮 Both percentages are derived rather than written twice: a future
# adjustment to the window or the ceiling would otherwise leave the message
# quoting a number the check no longer enforces.
percent=$(( fixes * 100 / window ))
ceiling_percent=$(( ceiling * 100 / window ))

if [[ "${fixes}" -gt "${ceiling}" ]]; then
    cat >&2 <<EOF
::error::fix ratio is ${fixes}/${window} (${percent}%), above the ${ceiling}/${window} (${ceiling_percent}%) ceiling

The repository is in stabilization mode. Until this ratio is back under ${ceiling_percent}%,
the only commits that belong on main are fixes, tests, documentation and
reverts — no new features.

A fix rate this high means the previous fixes did not hold. Adding a feature
on top of that adds a surface that will need its own repair pass.
EOF
    exit 1
fi

echo "👍 fix ratio is ${fixes}/${window} (${percent}%), under the ${ceiling}/${window} (60%) ceiling"
