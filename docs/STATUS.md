<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 John Knipper -->

# Status

| Part | State | Evidence |
|---|---|---|
| Tunnel engine | Works on macOS | `make test`: handshake, data both ways, forged, replayed and wrongly sourced packets dropped and counted, rekey after two minutes, keepalive, key expiry, unknown peer refused; built with address and undefined-behaviour sanitizers |
| Interoperability | Works against a commercial WireGuard server | `wgprobe` completes the handshake and gets a DNS answer through the tunnel |
| Configuration parser | Works | `make test` |
| `wireguard.device` for AROS | Works in PomAROS QEMU (AArch64, AROSTCP) | `tests/aros/qemu-test.sh`: the stack opens the device at boot, the tunnel comes up against a commercial WireGuard server, no task crashes |
| `WireGuard` command for AROS | Works in PomAROS QEMU | Same test: the address the Internet sees changes while the tunnel is up and returns after `DOWN`; names resolve through the tunnel's DNS server; `DOWN` wipes the keys in the device |
| Adding `wg0` to a running stack | Works, at a cost | Same test with `--runtime-add`. The command appends the interface line and has the stack read its configuration again, which renews the DHCP lease of the other interfaces |
| Native PomAROS on the M1 | Not tested | |
| IPv6 inside the tunnel | Not supported | AROSTCP has no IPv6 path for a point-to-point SANA-II device |
| Kill switch | Not written | Traffic leaves by the ordinary route when the tunnel is down |
| Keys in a keyring | Not written | The key is read from the configuration file at `UP` and lives in the device's memory until `DOWN` |
| Constant-time check of the primitives on the AROS compiler | Not done | |
| More than one peer or one tunnel | Not supported | One unit, one peer |

## Known limits

- `DOWN` restores the name servers by making the stack read its
  configuration again.
- `STATUS` counters are published every 400 ms and can trail the traffic.
- `EXITIP` asks `api.ipify.org` over plain HTTP. It is a test aid.
- The binaries are built against whichever AROS SDK is at hand. The device
  and the commands call exec, dos, timer, entropy, bsdsocket and miami
  through their library vectors and read no field of `ExecBase`, because that
  structure's layout differs between AROS builds.
