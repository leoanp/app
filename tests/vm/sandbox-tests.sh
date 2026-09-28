#!/bin/sh
# Runs the sandbox escape tests (tests/sandbox) as root on a Linux 6.12+
# kernel. Builds as the current user, then runs only the test program with
# sudo, so no build files end up owned by root.
#
#   tests/vm/sandbox-tests.sh [test-name-filter]
set -eu
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/target}"

cargo test -q -p app-sandbox
bin=$(cargo test -p sandbox-tests --test escape --no-run --message-format=json 2>/dev/null |
    sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1)
[ -n "$bin" ] || { echo "could not build the escape tests" >&2; exit 1; }
sudo "$bin" --include-ignored --test-threads=1 "$@"
