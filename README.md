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

## Use on AROS

Copy `wireguard.device` to `DEVS:Networks/` and `WireGuard` to `C:`. Then:

```
WireGuard UP FILE Work:my-tunnel.conf
WireGuard STATUS
WireGuard DOWN
```

`UP` adds the interface `wg0` to the TCP/IP stack if it is missing, gives it
the tunnel's address, routes the `AllowedIPs` through it and sets the
tunnel's DNS servers. The route to the endpoint stays on the gateway it had,
so the encrypted packets do not enter the tunnel they carry. `NOROUTE` and
`NODNS` leave routes or name servers alone. `DOWN` removes all of it and
wipes the keys.

To have the stack know `wg0` from boot, without the reload that `UP` needs
the first time, add this line to its `db/interfaces`:

```
wg0 DEV=DEVS:Networks/wireguard.device UNIT=0 NOTRACKING
```

### How it fits AROS

`wireguard.device` is a SANA-II device of the point-to-point kind, like a PPP
driver: the stack opens it, writes IP packets to it and parks read requests
on it. Its unit task owns a UDP socket on the same stack for the encrypted
side. It needs AROSTCP and `entropy.resource`.

## Build for AROS

```sh
aros/build.sh --sdk <build>/bin/<platform> --tools <build>/bin/darwin-aarch64/tools --crosstools <aros-crosstools>
```

This writes `build/aros/wireguard.device` and `build/aros/WireGuard`. The
build is out of the AROS tree: it runs `genmodule` for the device and links
the commands without the C library.

`tests/aros/qemu-test.sh` boots a PomAROS QEMU image with the result and a
real configuration file, and prints a verdict.

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
