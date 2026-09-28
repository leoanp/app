#!/bin/sh
# Runs inside the virtme-ng guest, as root (see the kernel-tests job in
# .github/workflows/ci.yml). Prepares what the kernel tests need, then runs
# each test program given as an argument.
#
#   ci-guest.sh WORKDIR TEST-PROGRAM...
#
# WORKDIR is a writable folder shared with the host (not under /tmp: the
# sandbox hides /tmp from apps).
set -eu
work=$1
shift

echo "guest kernel: $(uname -r), LSMs: $(cat /sys/kernel/security/lsm)"

# cgroup v2, if the guest's init did not mount it.
mountpoint -q /sys/fs/cgroup || mount -t cgroup2 cgroup2 /sys/fs/cgroup

# A filesystem with fs-verity: ext4 with the verity feature, on a loop device.
img="$work/verity.img"
truncate -s 2G "$img"
mkfs.ext4 -q -F -O verity "$img"
mkdir -p "$work/verity"
mount -o loop "$img" "$work/verity"
mkdir -p "$work/verity/sandbox"
chmod 755 "$work/verity" "$work/verity/sandbox"

export APP_TEST_DIR="$work/verity"
export APP_SANDBOX_TEST_DIR="$work/verity/sandbox"

status=0
for bin in "$@"; do
    echo "=== $bin"
    "$bin" --include-ignored --test-threads=1 || status=1
done
umount "$work/verity" || true
exit $status
