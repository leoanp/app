#!/bin/sh
# Runs the storage tests (object store, composefs) on a Linux 6.12+ kernel
# with a filesystem that supports fs-verity. Tests that mount need root, so
# the composefs test program runs with sudo.
#
#   tests/vm/storage-tests.sh [test-name-filter]
set -eu
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/target}"
export APP_TEST_DIR="${APP_TEST_DIR:-/var/tmp}"

cargo test -q -p app-objects -- --include-ignored "$@"
# Test programs only (the library's unit tests and tests/mount.rs).
bins=$(cargo test -p app-composefs --no-run --message-format=json 2>/dev/null |
    grep '"test":true' | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')
case "$bins" in
    *deps/mount-*) ;;
    *) echo "could not find the composefs mount tests (got: '$bins')" >&2; exit 1 ;;
esac
for bin in $bins; do
    sudo APP_TEST_DIR="$APP_TEST_DIR" "$bin" --include-ignored --test-threads=1 "$@"
done
