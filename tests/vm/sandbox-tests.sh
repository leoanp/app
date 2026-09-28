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
# Pick the test program itself (target kind "test"), not the helper binaries
# built alongside it.
bin=$(cargo test -p sandbox-tests --test escape --no-run --message-format=json 2>/dev/null |
    grep '"kind":\["test"\]' | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')
case "$bin" in
    */deps/escape-*) ;;
    *) echo "could not find the escape test program (got: '$bin')" >&2; exit 1 ;;
esac
sudo "$bin" --include-ignored --test-threads=1 "$@"
