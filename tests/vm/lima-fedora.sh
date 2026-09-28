#!/bin/sh
# Recreates the development VM from scratch on a Mac (Lima 2.x, Apple
# Silicon or Intel): Fedora 44 Cloud, kernel 6.19.10, pinned packages, Rust
# 1.98.1 and 1.88, the repository mounted read-write, and a btrfs root with
# fs-verity. Then checks that everything the tests need is really there.
#
#   tests/vm/lima-fedora.sh [VM-NAME]        (default name: app)
#
# Afterwards:
#   limactl shell --workdir "$PWD" app -- tests/vm/sandbox-tests.sh
#   limactl shell --workdir "$PWD" app -- tests/vm/storage-tests.sh
set -eu
name=${1:-app}
repo=$(cd "$(dirname "$0")/../.." && pwd)

command -v limactl >/dev/null || { echo "Install Lima first: brew install lima" >&2; exit 1; }
if limactl list -q | grep -qx "$name"; then
    echo "A VM named '$name' already exists. Remove it first (limactl delete --force $name) or pick another name." >&2
    exit 1
fi

limactl start --name="$name" --tty=false --mount-only "$repo:w" "$repo/tests/vm/lima-fedora.yaml"

echo "--- checking the VM"
limactl shell --workdir "$repo" "$name" -- sh -eu -c '
    . "$HOME/.cargo/env"
    want() { printf "%-28s %s\n" "$1" "$2"; [ "$2" = "$3" ] || { echo "  expected: $3" >&2; exit 1; }; }
    want "Fedora release"   "$(. /etc/os-release; echo "$VERSION_ID")"            44
    want "kernel"           "$(uname -r | cut -d- -f1)"                          6.19.10
    want "Landlock"         "$(grep -o landlock /sys/kernel/security/lsm)"         landlock
    want "root filesystem"  "$(findmnt -no FSTYPE /var)"                          btrfs
    want "composefs"        "$(rpm -q --qf %{version} composefs)"                 1.0.8
    want "libseccomp"       "$(rpm -q --qf %{version} libseccomp-devel)"          2.6.0
    want "rustc"            "$(rustc --version | cut -d" " -f2)"                  1.98.1
    want "rustc (MSRV)"     "$(rustc +1.88 --version | cut -d" " -f2)"            1.88.0
    probe=$(mktemp -p /var/tmp)
    echo probe > "$probe"
    fsverity enable "$probe" && echo "fs-verity on /var/tmp       ok"
    rm -f "$probe"
    test -w "$PWD" && echo "repository mounted          read-write"
'
echo "--- VM '$name' is ready"
