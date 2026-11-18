<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 John Knipper -->

# Third-party code

| Directory | Origin | Revision | Licence |
|---|---|---|---|
| `wireguard-lwip/` | <https://github.com/smartalock/wireguard-lwip>, `src/wireguard.c`, `wireguard.h`, `wireguard-platform.h`, `crypto.c`, `crypto.h`, `crypto/refc/` | `cfba91666590e86bd67842c71cedf9a423be823a` | BSD-3-Clause (`wireguard-lwip/LICENSE`); X25519 by Mike Hamburg, MIT (`crypto/refc/x25519-license.txt`); Poly1305 by Andrew Moon, public domain or MIT; BLAKE2s from RFC 7693 |

The files are copied unmodified. The lwIP interface glue of that project
(`wireguardif.c`) is left out; `src/wg_tunnel.c` adapts its peer state
machine and carries its copyright notice. `compat/lwip/` supplies the four
type names the core takes from lwIP headers.

To update: copy the same files from a newer revision, change the revision
above, run `make test` and `wgprobe` against a real peer.
