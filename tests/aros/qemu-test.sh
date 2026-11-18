#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 John Knipper
#
# Boots a PomAROS QEMU image with wireguard.device and the WireGuard command
# on it, brings a tunnel up from a real configuration file and prints one
# verdict line.
#
#   tests/aros/qemu-test.sh --launcher <pomaros-qemu binary> --resources <dir with System.img> \
#       --config <wireguard .conf> --work <empty scratch dir> [--runtime-add] [--timeout 110]
#
# The image must already be built with aros/build.sh (build/aros/). The
# configuration file holds a private key: the scratch directory, which
# receives a disk image containing it, is deleted when the test ends.
#
# --runtime-add leaves wg0 out of the stack's interface list, so the command
# has to add it and make the stack read its configuration again.
#
# The exit address the Internet sees is compared before, during and after
# the tunnel. The addresses themselves are not printed.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
launcher= resources= config= work= runtime_add=0 timeout=110
while [ $# -gt 0 ]; do
    case "$1" in
        --launcher) launcher=$2; shift 2 ;;
        --resources) resources=$2; shift 2 ;;
        --config) config=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --timeout) timeout=$2; shift 2 ;;
        --runtime-add) runtime_add=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[ -n "$launcher" ] && [ -n "$resources" ] && [ -n "$config" ] && [ -n "$work" ] || {
    echo "usage: qemu-test.sh --launcher BIN --resources DIR --config FILE --work DIR [--runtime-add] [--timeout N]" >&2
    exit 64; }
for f in "$launcher" "$resources/System.img" "$config" "$repo/build/aros/wireguard.device" \
         "$repo/build/aros/WireGuard" "$repo/build/aros/RunScript"; do
    [ -e "$f" ] || { echo "missing: $f" >&2; exit 66; }
done
command -v mcopy >/dev/null || { echo "mtools is required" >&2; exit 69; }
[ ! -e "$work" ] || [ -z "$(ls -A "$work")" ] || { echo "the work directory must be empty: $work" >&2; exit 73; }

mkdir -p "$work/profile"
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp "$resources/System.img" "$work/profile/system.img"
# The WORK volume, a FAT file system, starts 64 MiB into the image.
vol="$work/profile/system.img@@67108864"

cat > "$work/script" <<'SCRIPT'
FailAt 21
SYS:C/Wait 12
VMWORK0:WireGuard EXITIP >VMWORK0:wg-before.log
VMWORK0:WireGuard UP FILE VMWORK0:wg.conf >VMWORK0:wg-up.log
SYS:C/Wait 4
VMWORK0:WireGuard EXITIP >VMWORK0:wg-during.log
VMWORK0:WireGuard STATUS >VMWORK0:wg-status.log
VMWORK0:WireGuard DOWN >VMWORK0:wg-down.log
SYS:C/Wait 6
VMWORK0:WireGuard EXITIP >VMWORK0:wg-after.log
VMWORK0:WireGuard STATUS >VMWORK0:wg-end.log
SCRIPT

if [ "$runtime_add" = 0 ]; then
    mtype -i "$vol" ::/System/System/Network/AROSTCP/db/interfaces > "$work/interfaces"
    printf 'wg0 DEV=DEVS:Networks/wireguard.device UNIT=0 NOTRACKING\n' >> "$work/interfaces"
    mcopy -o -i "$vol" "$work/interfaces" ::/System/System/Network/AROSTCP/db/interfaces
fi
# The image's startup runs C:ConClip; the helper takes its place and runs the script.
mcopy -o -i "$vol" "$repo/build/aros/RunScript" ::/System/C/ConClip
mcopy -o -i "$vol" "$work/script" ::/wg-test.script
mcopy -o -i "$vol" "$repo/build/aros/wireguard.device" ::/System/Devs/Networks/wireguard.device
mcopy -o -i "$vol" "$repo/build/aros/WireGuard" ::/WireGuard
mcopy -o -i "$vol" "$config" ::/wg.conf

"$launcher" --resources "$resources" --profile "$work/profile" --headless --timeout "$timeout" \
    > "$work/launcher.log" 2>&1 || true

read_log() { mtype -i "$vol" "::/$1" 2>/dev/null || true; }
field() { printf '%s\n' "$1" | sed -n "s/.*[[:space:]]$2=\([^[:space:]]*\).*/\1/p" | head -1; }

before=$(field "$(read_log wg-before.log)" exitip)
during=$(field "$(read_log wg-during.log)" exitip)
after=$(field "$(read_log wg-after.log)" exitip)
status=$(read_log wg-status.log)
end=$(read_log wg-end.log)
up=$(field "$status" up)
bad=$(field "$status" bad-auth)
down=$(field "$end" configured)
crashes=$(grep -a -c "task crashed" "$work/profile/serial.log" 2>/dev/null || true)

changed=0; restored=0
[ -n "$before" ] && [ -n "$during" ] && [ "$before" != "$during" ] && changed=1
[ -n "$before" ] && [ "$before" = "$after" ] && restored=1

verdict=FAIL
[ "$changed" = 1 ] && [ "$restored" = 1 ] && [ "$up" = 1 ] && [ "$down" = 0 ] && [ "${crashes:-0}" = 0 ] && verdict=PASS
echo "[WGQEMU] $verdict runtime-add=$runtime_add handshake=${up:-0} exit-ip-changed=$changed" \
     "exit-ip-restored=$restored dns-resolved=$([ -n "$during" ] && echo 1 || echo 0)" \
     "keys-wiped-on-down=$([ "$down" = 0 ] && echo 1 || echo 0) bad-auth=${bad:-?} crashes=${crashes:-0}"
[ "$verdict" = PASS ] || {
    echo "--- up"; read_log wg-up.log
    echo "--- status"; printf '%s\n' "$status"
    echo "--- serial"; grep -a "wireguard\|crashed\|crash fault" "$work/profile/serial.log" | head -20
}
[ "$verdict" = PASS ]
