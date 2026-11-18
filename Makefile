# SPDX-License-Identifier: MIT
# Copyright (c) 2026 John Knipper
#
# Host side: the tunnel engine, its tests and the wgprobe tool, built with the
# system compiler. The AROS device and command are built by aros/build.sh.

CC ?= cc
CFLAGS ?= -O2 -g
WARN := -std=gnu11 -Wall -Wextra -Werror -Wno-unused-parameter
CORE := third_party/wireguard-lwip
INCLUDES := -Icompat -I$(CORE) -Isrc
# The vendored core is built as it comes, with its own warnings left alone.
CORE_SRC := $(CORE)/wireguard.c $(CORE)/crypto.c $(CORE)/crypto/refc/blake2s.c $(CORE)/crypto/refc/chacha20.c \
            $(CORE)/crypto/refc/chacha20poly1305.c $(CORE)/crypto/refc/poly1305-donna.c $(CORE)/crypto/refc/x25519.c
OUR_SRC := src/wg_tunnel.c src/wg_config.c host/platform_posix.c
B := build/host

all: $(B)/wgprobe $(B)/test_tunnel

$(B)/core.a: $(CORE_SRC)
	@mkdir -p $(B)/core
	@for f in $(CORE_SRC); do $(CC) $(CFLAGS) -std=gnu11 -w $(INCLUDES) -c $$f -o $(B)/core/$$(basename $$f .c).o || exit 1; done
	@ar rcs $@ $(B)/core/*.o

$(B)/wgprobe: host/wgprobe.c $(OUR_SRC) $(B)/core.a src/*.h
	$(CC) $(CFLAGS) $(WARN) $(INCLUDES) host/wgprobe.c $(OUR_SRC) $(B)/core.a -o $@

$(B)/test_tunnel: tests/test_tunnel.c $(OUR_SRC) $(B)/core.a src/*.h
	$(CC) $(CFLAGS) $(WARN) -fsanitize=address,undefined $(INCLUDES) tests/test_tunnel.c $(OUR_SRC) $(B)/core.a -o $@

test: $(B)/test_tunnel
	$(B)/test_tunnel

clean:
	rm -rf build

.PHONY: all test clean
