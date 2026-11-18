#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 John Knipper
#
# Builds wireguard.device and the WireGuard command for AROS AArch64, out of
# the AROS tree, against an existing AROS SDK.
#
#   aros/build.sh --sdk <build>/bin/<platform> --tools <build>/bin/darwin-aarch64/tools \
#                 --crosstools <aros-crosstools> [--out build/aros] [--debug]
#
# The code is built without x18 and with the large code model, so one binary
# runs on hosted, VM and native AROS.

set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sdk= tools= crosstools= out="$repo/build/aros" debug=0
while [ $# -gt 0 ]; do
    case "$1" in
        --sdk) sdk=$2; shift 2 ;;
        --tools) tools=$2; shift 2 ;;
        --crosstools) crosstools=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --debug) debug=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[ -n "$sdk" ] && [ -n "$tools" ] && [ -n "$crosstools" ] || {
    echo "usage: aros/build.sh --sdk DIR --tools DIR --crosstools DIR [--out DIR] [--debug]" >&2; exit 64; }

clang="$crosstools/bin/clang"
nm="$crosstools/bin/llvm-nm"
genmodule="$tools/genmodule"
developer="$sdk/AROS/Developer"
generated="$sdk/gen/include"
for f in "$clang" "$nm" "$genmodule" "$developer/lib/startup.o" "$developer/include/devices/sana2.h"; do
    [ -e "$f" ] || { echo "missing: $f" >&2; exit 66; }
done

arch="-mcmodel=large -ffixed-x18"
core="$repo/third_party/wireguard-lwip"
mod="$out/module"
obj="$out/obj"
rm -rf "$mod" "$obj"
mkdir -p "$mod/include" "$obj"

"$genmodule" -c "$repo/aros/wireguard.conf" -d "$mod" writelibdefs wireguard device
"$genmodule" -c "$repo/aros/wireguard.conf" -d "$mod" writefiles wireguard device

dbg=
[ "$debug" = 1 ] && dbg="-DDEBUG=1"
common="-D__arm64__ -D__AROS__ -O2 -std=gnu11 -fno-builtin -fno-stack-protector"
inc="-I $generated -I $developer/include -I $developer/include/aros/stdc -I $developer/include/aros/posixc -I $repo/aros -I $repo/src -I $repo/compat -I $core -I $mod -I $mod/include"

cc_dev() { # source object extra-flags...
    src=$1; o=$2; shift 2
    # shellcheck disable=SC2086
    "$clang" --target=aarch64-unknown-none-elf $arch $common -D__NOLIBBASE__ $dbg \
        -DLC_LIBDEFS_FILE='"wireguard_libdefs.h"' $inc "$@" -c "$src" -o "$o"
}

objs=
for s in wireguard_start wireguard_end; do
    cc_dev "$mod/$s.c" "$obj/$s.o" -w
done
for s in wg_device wg_task wg_ministring; do
    cc_dev "$repo/aros/$s.c" "$obj/$s.o" -Wall -Wextra -Werror -Wno-unused-parameter -Wno-pointer-sign
    objs="$objs $obj/$s.o"
done
cc_dev "$repo/src/wg_tunnel.c" "$obj/wg_tunnel.o" -Wall -Wextra -Werror -Wno-unused-parameter
objs="$objs $obj/wg_tunnel.o"
for s in wireguard crypto crypto/refc/blake2s crypto/refc/chacha20 crypto/refc/chacha20poly1305 \
         crypto/refc/poly1305-donna crypto/refc/x25519; do
    o="$obj/core_$(basename "$s").o"
    cc_dev "$core/$s.c" "$o" -w
    objs="$objs $o"
done

# shellcheck disable=SC2086
PATH="$tools:$PATH" COMPILER_PATH="$crosstools/bin" "$clang" --target=aarch64-unknown-aros $arch \
    -nostartfiles -Wl,--allow-multiple-definition -L "$developer/lib" -L "$crosstools/lib/generic" \
    -o "$out/wireguard.device" "$obj/wireguard_start.o" $objs "$obj/wireguard_end.o" \
    -Wl,--start-group -lamiga -larossupport -laros -lexec -lautoinit -llibinit -Wl,--end-group \
    -lclang_rt.builtins-aarch64

undefined=$("$nm" --undefined-only "$out/wireguard.device" | grep -E '[^[:space:]]' || true)
[ -z "$undefined" ] || { echo "unresolved symbols in wireguard.device:" >&2; echo "$undefined" >&2; exit 65; }
for symbol in WireGuard_5_WG_BeginIO WireGuard_6_WG_AbortIO WireGuard_ROMTag; do
    "$nm" --defined-only "$out/wireguard.device" | grep -Eq "[[:space:]]$symbol\$" || {
        echo "missing symbol in wireguard.device: $symbol" >&2; exit 65; }
done
echo "built $out/wireguard.device"

if [ -f "$repo/aros/wg_command.c" ]; then
    # shellcheck disable=SC2086
    COMPILER_PATH="$tools:$crosstools/bin" "$clang" --target=aarch64-unknown-aros $arch -O2 -std=gnu11 \
        -Wall -Wextra -Werror -Wno-unused-parameter -Wno-pointer-sign \
        -isystem "$developer/include" -isystem "$generated" -isystem "$developer/include/aros/stdc" -isystem "$developer/include/aros/posixc" \
        -I "$repo/aros" -I "$repo/src" -I "$repo/compat" -I "$core" \
        -nostartfiles -nodefaultlibs -L "$developer/lib" -L "$crosstools/lib/generic" \
        "$developer/lib/startup.o" "$repo/aros/wg_command.c" "$repo/src/wg_config.c" \
        "$core/wireguard.c" "$core/crypto.c" "$core/crypto/refc/blake2s.c" "$core/crypto/refc/chacha20.c" \
        "$core/crypto/refc/chacha20poly1305.c" "$core/crypto/refc/poly1305-donna.c" "$core/crypto/refc/x25519.c" \
        -Wno-error -w -o "$out/WireGuard" \
        -Wl,--allow-multiple-definition -Wl,--start-group -lstdc -lstdcio -ldos -lexec -laros -lautoinit -llibinit \
        -lutility -lamiga -larossupport -Wl,--end-group -lclang_rt.builtins-aarch64
    echo "built $out/WireGuard"
fi
