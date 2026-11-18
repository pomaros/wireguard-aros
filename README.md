<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 John Knipper -->

# wireguard-aros

A WireGuard VPN client for [AROS](https://www.aros.org/), made for
[PomAROS](https://pomaros.com/).

It has three parts:

- **A tunnel engine** (`src/`) with no network stack under it. The caller gives
  it a function that sends a UDP datagram and a function that receives a
  decrypted IP packet. The cryptography and the handshake come from
  [wireguard-lwip](https://github.com/smartalock/wireguard-lwip), unmodified
  (`third_party/`).
- **A host tool and tests** (`host/`, `tests/`) that run the engine on macOS or
  Linux.
- **An AROS network device** (`aros/`), `wireguard.device`, which the AROS
  TCP/IP stack opens like any other SANA-II driver, and the `WireGuard`
  command that brings a tunnel up from a configuration file.

See [docs/STATUS.md](docs/STATUS.md) for what works.

## Use on a host

```sh
make test
build/host/wgprobe my-tunnel.conf example.com
```

`wgprobe` reads a standard WireGuard configuration file, completes the
handshake with its peer over a plain UDP socket and resolves one name by
sending a DNS query inside the tunnel. It creates no network interface and
needs no privileges. Its last line is a verdict:

```
[WGPROBE] PASS handshake=1 handshake-ms=269 initiations=1 dns-reply=1 reply-ms=438 answers=1 name=example.com ...
```

## Configuration

The standard `wg-quick` file with one `[Interface]` and one `[Peer]`:
`PrivateKey`, `Address`, `DNS`, `MTU`, `ListenPort`, `PublicKey`,
`PresharedKey`, `AllowedIPs`, `Endpoint`, `PersistentKeepalive`. IPv6
addresses and prefixes in the file are skipped: the tunnel carries IPv4.

A configuration file holds a private key. `*.conf` is ignored by git here.

## Licence

Our code is MIT, see [LICENSE](LICENSE). `src/wg_tunnel.c` and
`src/wg_tunnel.h` adapt BSD-3-Clause code and keep that licence. Vendored
code keeps its own, see [third_party/README.md](third_party/README.md).

"WireGuard" is a registered trademark of Jason A. Donenfeld. This project is
independent of the WireGuard project.
