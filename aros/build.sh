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

# The commands: no C library, no SDK startup code. The object with the entry
# point comes first on the link line.
cc_cmd() { # source object extra-flags...
    src=$1; o=$2; shift 2
    # shellcheck disable=SC2086
    "$clang" --target=aarch64-unknown-none-elf $arch $common $inc "$@" -c "$src" -o "$o"
}
link_cmd() { # output objects...
    o=$1; shift
    # shellcheck disable=SC2086
    PATH="$tools:$PATH" COMPILER_PATH="$crosstools/bin" "$clang" --target=aarch64-unknown-aros $arch \
        -nostartfiles -nodefaultlibs -Wl,--allow-multiple-definition -L "$developer/lib" -L "$crosstools/lib/generic" \
        -o "$o" "$@" -Wl,--start-group -lamiga -larossupport -laros -lexec -Wl,--end-group -lclang_rt.builtins-aarch64
    undefined=$("$nm" --undefined-only "$o" | grep -E '[^[:space:]]' || true)
    [ -z "$undefined" ] || { echo "unresolved symbols in $o:" >&2; echo "$undefined" >&2; exit 65; }
    echo "built $o"
}
strict="-Wall -Wextra -Werror -Wno-unused-parameter -Wno-pointer-sign"
cc_cmd "$repo/aros/wg_command.c" "$obj/cmd_main.o" $strict
cc_cmd "$repo/aros/wg_printf.c" "$obj/cmd_printf.o" $strict
cc_cmd "$repo/aros/wg_ministring.c" "$obj/cmd_string.o" $strict
cc_cmd "$repo/src/wg_config.c" "$obj/cmd_config.o" $strict
cc_cmd "$core/wireguard.c" "$obj/cmd_core.o" -w
cc_cmd "$core/crypto.c" "$obj/cmd_crypto.o" -w
link_cmd "$out/WireGuard" "$obj/cmd_main.o" "$obj/cmd_printf.o" "$obj/cmd_string.o" "$obj/cmd_config.o" \
    "$obj/cmd_core.o" "$obj/cmd_crypto.o" "$obj/core_blake2s.o" "$obj/core_chacha20.o" \
    "$obj/core_chacha20poly1305.o" "$obj/core_poly1305-donna.o" "$obj/core_x25519.o"
cc_cmd "$repo/tests/aros/runscript.c" "$obj/runscript.o" $strict
link_cmd "$out/RunScript" "$obj/runscript.o"
